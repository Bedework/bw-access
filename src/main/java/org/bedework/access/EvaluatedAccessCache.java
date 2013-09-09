/* ********************************************************************
    Licensed to Jasig under one or more contributor license
    agreements. See the NOTICE file distributed with this work
    for additional information regarding copyright ownership.
    Jasig licenses this file to you under the Apache License,
    Version 2.0 (the "License"); you may not use this file
    except in compliance with the License. You may obtain a
    copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on
    an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied. See the License for the
    specific language governing permissions and limitations
    under the License.
*/
package org.bedework.access;

import org.bedework.access.Acl.CurrentAccess;

import org.apache.log4j.Logger;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/** This provides a cache of evaluated CurrentAccess objects. Rather than create
 * a composite key, which itself involves creating a new object per search, we
 * instead create a hierarchical set of tables, each indexed by an element of the
 * key. These levels are: <ul>
 * <li>owner href: the owner of the entity</li>
 * <li>accessor href: who's trying to get access</li>
 * <li>desired access</li>
 * <li>max access: filters the allowed access</li>
 * <li>acl: a string representation of the acl</li>
 *
 * @author douglm
 *
 */
public class EvaluatedAccessCache implements Serializable {
  private transient static Logger log;

  private static Object synch = new Object();

  private static class AccessMap extends HashMap<String, CurrentAccess>{};

  private static class PrivMap extends HashMap<PrivilegeSet, AccessMap>{};

  private static class PrivSetMap extends HashMap<PrivilegeSet, PrivMap>{};

  private static class AccessorsMap extends HashMap<String, PrivSetMap>{};

  private static Map<String, AccessorsMap> ownerHrefs = new HashMap<String, AccessorsMap>();

  /* Back end of the queue is the most recently referenced. */
  private static LinkedList<String> accessorQueue = new LinkedList<String>();

  private static Access.AccessStatsEntry accessorQueueLen =
    new Access.AccessStatsEntry("Access cache accessor queue len");

  private static Access.AccessStatsEntry numGets =
    new Access.AccessStatsEntry("Access cache gets");

  private static Access.AccessStatsEntry numHits =
    new Access.AccessStatsEntry("Access cache hits");

  private static Access.AccessStatsEntry numAclTables =
    new Access.AccessStatsEntry("Access cache ACL tables");

  private static Access.AccessStatsEntry numEntries =
    new Access.AccessStatsEntry("Access cache entries");

  private static Collection<Access.AccessStatsEntry> stats = new ArrayList<Access.AccessStatsEntry>();

  static {
    stats.add(accessorQueueLen);
    stats.add(numGets);
    stats.add(numHits);
    stats.add(numAclTables);
    stats.add(numEntries);
  }

  /**
   * @param ownerHref
   * @param accessorHref
   * @param desiredPriv
   * @param maxAccess
   * @param acl
   * @return CurrentAccess or null
   */
  public static CurrentAccess get(final String ownerHref,
                                  final String accessorHref,
                                  final PrivilegeSet desiredPriv,
                                  final PrivilegeSet maxAccess,
                                  final String acl) {
    numGets.count++;

    synchronized (synch) {
      AccessorsMap accessors = ownerHrefs.get(ownerHref);

      if (accessors == null) {
        return null;
      }

      /* ===================== desired priv ================== */

      PrivSetMap desiredPrivs = accessors.get(accessorHref);

      if (desiredPrivs == null) {
        return null;
      }

      accessorQueue.remove(accessorHref);
      accessorQueue.add(accessorHref);

      /* ===================== max priv ================== */

      PrivMap maxPrivs = desiredPrivs.get(desiredPriv);

      if (maxPrivs == null) {
        return null;
      }

      /* ===================== acl ================== */

      AccessMap acls = maxPrivs.get(maxAccess);

      if (acls == null) {
        return null;
      }

      /* ==================== finally access =============== */

      CurrentAccess ca = acls.get(acl);

      if (ca != null) {
        numHits.count++;
      }

      return ca;
    } // synch
  }

  /**
   * @param ownerHref
   * @param accessorHref
   * @param desiredPriv
   * @param maxAccess
   * @param acl
   * @param ca
   */
  public static void put(final String ownerHref,
                         final String accessorHref,
                         final PrivilegeSet desiredPriv,
                         final PrivilegeSet maxAccess,
                         final String acl,
                         final CurrentAccess ca) {
    boolean found = true;


    synchronized (synch) {
      AccessorsMap accessors = ownerHrefs.get(ownerHref);

      if (accessors == null) {
        accessors = new AccessorsMap();
        ownerHrefs.put(ownerHref, accessors);
        found = false;
      }

      accessorQueue.remove(accessorHref);
      accessorQueue.add(accessorHref);

      /* ===================== desired priv ================== */

      PrivSetMap desiredPrivs = null;
      if (found) {
        // Try a search
        desiredPrivs = accessors.get(accessorHref);
      }

      if (desiredPrivs == null) {
        desiredPrivs = new PrivSetMap();
        accessors.put(accessorHref, desiredPrivs);
        found = false;
      }

      /* ===================== max priv ================== */

      PrivMap maxPrivs = null;
      if (found) {
        // Try a search
        maxPrivs = desiredPrivs.get(desiredPriv);
      }

      if (maxPrivs == null) {
        maxPrivs = new PrivMap();
        desiredPrivs.put(desiredPriv, maxPrivs);
        found = false;
      }

      /* ===================== acl ================== */

      AccessMap acls = null;
      if (found) {
        // Try a search
        acls = maxPrivs.get(maxAccess);
      }

      if (acls == null) {
        acls = new AccessMap();
        maxPrivs.put(maxAccess, acls);
        numAclTables.count++;
        found = false;
      }

      /* ==================== finally store =============== */

      if (found) {
        // Let's see if it's the same - it ought to be

        CurrentAccess tca = acls.get(acl);
        if (tca != null) {
          if (!tca.equals(ca)) {
            // That's bad.
            error("Current access in table does not match, table:" + tca +
                  " new version " + ca);
          }
        }
      }

      numEntries.count++;
      acls.put(acl, ca);
    } // synch
  }

  /** Get the cache statistics
   *
   * @return Collection of stats
   */
  public static Collection<Access.AccessStatsEntry> getStatistics() {
    accessorQueueLen.count = accessorQueue.size();

    return stats;
  }

  private static Logger getLog() {
    if (log == null) {
      log = Logger.getLogger(EvaluatedAccessCache.class.getName());
    }

    return log;
  }

  private static void error(final String msg) {
    getLog().error(msg);
  }
}
