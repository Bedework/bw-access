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

import org.bedework.util.logging.BwLogger;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import static org.bedework.access.Acl.decode;
import static org.bedework.access.Acl.evaluations;
import static org.bedework.access.Acl.privSets;
import static org.bedework.access.Acl.usePool;
import static org.bedework.access.PrivilegeDefs.allowed;
import static org.bedework.access.PrivilegeDefs.allowedInherited;
import static org.bedework.access.PrivilegeDefs.privReadAcl;
import static org.bedework.access.PrivilegeDefs.privWriteAcl;

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
  private final static Object synch = new Object();

  private static class AccessMap extends HashMap<String, CurrentAccess>{}

  private static class PrivMap extends HashMap<PrivilegeSet, AccessMap>{}

  private static class PrivSetMap extends HashMap<PrivilegeSet, PrivMap>{}

  private static class AccessorsMap extends HashMap<String, PrivSetMap>{}

  private static final Map<String, AccessorsMap> ownerHrefs = new HashMap<>();

  /* Back end of the queue is the most recently referenced. */
  private static final LinkedList<String> accessorQueue = new LinkedList<>();

  private static final Access.AccessStatsEntry accessorQueueLen =
    new Access.AccessStatsEntry("Access cache accessor queue len");

  private static final Access.AccessStatsEntry numGets =
    new Access.AccessStatsEntry("Access cache gets");

  private static final Access.AccessStatsEntry numHits =
    new Access.AccessStatsEntry("Access cache hits");

  private static final Access.AccessStatsEntry numAclTables =
    new Access.AccessStatsEntry("Access cache ACL tables");

  private static final Access.AccessStatsEntry numEntries =
    new Access.AccessStatsEntry("Access cache entries");

  private static final Collection<Access.AccessStatsEntry> stats = new ArrayList<>();

  private static final BwLogger logger =
          new BwLogger().setLoggedClass(EvaluatedAccessCache.class);

  static {
    stats.add(accessorQueueLen);
    stats.add(numGets);
    stats.add(numHits);
    stats.add(numAclTables);
    stats.add(numEntries);
  }

  /**
   * @param ownerHref     href
   * @param accessorHref  href
   * @param desiredPriv   priv set
   * @param maxAccess     max allowed
   * @param acl           String acl
   * @return CurrentAccess or null
   */
  public static CurrentAccess get(final String ownerHref,
                                  final String accessorHref,
                                  final PrivilegeSet desiredPriv,
                                  final PrivilegeSet maxAccess,
                                  final String acl) {
    numGets.count++;

    synchronized (synch) {
      final AccessorsMap accessors = ownerHrefs.get(ownerHref);

      if (accessors == null) {
        return null;
      }

      /* ===================== desired priv ================== */

      final PrivSetMap desiredPrivs = accessors.get(accessorHref);

      if (desiredPrivs == null) {
        return null;
      }

      accessorQueue.remove(accessorHref);
      accessorQueue.add(accessorHref);

      /* ===================== max priv ================== */

      final PrivMap maxPrivs = desiredPrivs.get(desiredPriv);

      if (maxPrivs == null) {
        return null;
      }

      /* ===================== acl ================== */

      final AccessMap acls = maxPrivs.get(maxAccess);

      if (acls == null) {
        return null;
      }

      /* ==================== finally access =============== */

      final CurrentAccess ca = acls.get(acl);

      if (ca != null) {
        numHits.count++;
      }

      return ca;
    } // synch
  }

  /**
   * @param ownerHref     href
   * @param accessorHref  href
   * @param desiredPriv   priv set
   * @param maxAccess     max allowed
   * @param acl           String acl
   * @param ca            current access object
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

        final CurrentAccess tca = acls.get(acl);
        if (tca != null) {
          if (!tca.equals(ca)) {
            // That's bad.
            logger.error("Current access in table does not match, " +
                                  "table:" + tca +
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

  /** Evaluating an ACL
   *
   * <p>The process of evaluating access is as follows:
   *
   * <p>For an unauthenticated (guest) user we look for an entry with an
   * unauthenticated 'who' field. If none exists access is denied othewise the
   * indicated privileges are used to determine access.
   *
   * <p>If the principal is authenticated there are a number of steps in the process
   * which are executed in the following order:
   *
   * <ol>
   * <li>If the principal is the owner then use the given access or the default.</li>
   *
   * <li>If there are specific ACEs for the user use the merged access. </li>
   *
   * <li>Find all group entries for the given user's groups. If there is more than
   * one combine them with the more permissive taking precedence, e.g
   * write allowed overrides write denied
   * <p>If any group entries were found we're done.</li>
   *
   * <li>if there is an 'other' entry (i.e. not Owner) use that.</li>
   *
   * <li>if there is an authenticated entry use that.</li>
   *
   * <li>Otherwise apply defaults - for the owner full acccess, for any others no
   * access</li>
   *
   * @param cb callback to makeHref
   * @param who we are evaluating access for
   * @param owner of resource
   * @param how access is desired
   * @param aclChars encoded acl chars
   * @param filter    if not null specifies maximum access
   * @return CurrentAccess   access + allowed/disallowed
   */
  public static CurrentAccess evaluateAccess(final Access.AccessCb cb,
                                             final AccessPrincipal who,
                                             final AccessPrincipal owner,
                                             final Privilege[] how,
                                             final char[] aclChars,
                                             final PrivilegeSet filter) {
    final String aclString = new String(aclChars);
    final PrivilegeSet howPriv = PrivilegeSet.makePrivilegeSet(how);

    CurrentAccess ca = get(owner.getPrincipalRef(),
                           who.getPrincipalRef(),
                           howPriv, filter,
                           aclString);

    if (ca != null) {
      return ca;
    }

    ca = evaluateAccessInt(cb, who, owner, how, aclChars, filter);

    put(owner.getPrincipalRef(),
        who.getPrincipalRef(),
        howPriv, filter,
        aclString,
        ca);

    return ca;
  }

  private static class DebugBuff {
    private StringBuilder buffer;
    private StringBuilder sb() {
      if (buffer == null) {
        buffer = new StringBuilder();
      }
      return buffer;
    }

    DebugBuff append(final boolean val) {
      append(String.valueOf(val));

      return this;
    }

    DebugBuff append(final String val) {
      sb().append(val);

      return this;
    }

    public String toString() {
      return sb().toString();
    }
  }

  private static CurrentAccess evaluateAccessInt(
          final Access.AccessCb cb,
          final AccessPrincipal who,
          final AccessPrincipal owner,
          final Privilege[] how,
          final char[] aclChars,
          final PrivilegeSet filter) {
    evaluations.count++;

    final boolean authenticated = !who.getUnauthenticated();
    boolean isOwner = false;
    final CurrentAccess ca = new CurrentAccess();

    final Acl acl = decode(aclChars);
    ca.acl = acl;
    ca.aclChars = aclChars;

    if (authenticated) {
      isOwner = who.equals(owner);
    }

    final DebugBuff debugsb = new DebugBuff();

    if (logger.debug()) {
      if (aclChars == null) {
        debugsb.append("NULL");
      } else {
        debugsb.append(new String(aclChars));
      }
      debugsb.append("'\n");

      if (authenticated) {
        debugsb.append("   with authenticated principal ")
               .append(who.getPrincipalRef());
      } else {
        debugsb.append("   unauthenticated ");
      }
      debugsb.append(" isOwner = ")
             .append(isOwner)
             .append("'\n");
    }

    if (aclChars == null) {
      return ca;
    }

    getPrivileges: {
      if (!authenticated) {
        ca.privileges = Ace.findMergedPrivilege(acl, cb, null,
                                                Ace.whoTypeUnauthenticated);

        if (ca.privileges == null) {
          // All might be available
          ca.privileges = Ace.findMergedPrivilege(acl, cb, null, Ace.whoTypeAll);
        }

        if (ca.privileges != null) {
          if (logger.debug()) {
            debugsb.append("... For unauthenticated got: ")
                   .append(ca.privileges.toString())
                   .append("'\n");
          }

          break getPrivileges;
        }
      }

      if (isOwner) {
        ca.privileges = Ace.findMergedPrivilege(acl, cb, null, Ace.whoTypeOwner);
        if (ca.privileges == null) {
          ca.privileges = PrivilegeSet.makeDefaultOwnerPrivileges();
        }

        if (logger.debug()) {
          debugsb.append("... For owner got: ")
                 .append(ca.privileges.toString())
                 .append("'\n");
        }

        break getPrivileges;
      }

      // Not owner - look for user
      ca.privileges = Ace.findMergedPrivilege(acl, cb,
                                              who.getPrincipalRef(),
                                              Ace.whoTypeUser);

      // Treat resources, tickets, hosts and venues like user
      // XXX This assumes the account name is distinguishable.
      if (ca.privileges == null) {
        ca.privileges = Ace.findMergedPrivilege(acl, cb,
                                                who.getPrincipalRef(),
                                                Ace.whoTypeResource);
      }
      if (ca.privileges == null) {
        ca.privileges = Ace.findMergedPrivilege(acl, cb,
                                                who.getPrincipalRef(),
                                                Ace.whoTypeTicket);
      }
      if (ca.privileges == null) {
        ca.privileges = Ace.findMergedPrivilege(acl, cb,
                                                who.getPrincipalRef(),
                                                Ace.whoTypeVenue);
      }
      if (ca.privileges == null) {
        ca.privileges = Ace.findMergedPrivilege(acl, cb,
                                                who.getPrincipalRef(),
                                                Ace.whoTypeHost);
      }

      if (ca.privileges != null) {
        if (logger.debug()) {
          debugsb.append("... For user got: ")
                 .append(ca.privileges.toString())
                 .append("'\n");
        }

        break getPrivileges;
      }

      // No specific user access - look for group access

      if (who.getGroupNames() != null) {
        for (final String group: who.getGroupNames()) {
          if (logger.debug()) {
            debugsb.append("...Try access for group ")
                   .append(group)
                   .append("'\n");
          }
          final PrivilegeSet privs =
                  Ace.findMergedPrivilege(acl, cb, group,
                                          Ace.whoTypeGroup);
          if (privs != null) {
            ca.privileges = PrivilegeSet.mergePrivileges(ca.privileges, privs,
                                                         false);
          }
        }
      }

      if (ca.privileges != null) {
        if (logger.debug()) {
          debugsb.append("...For groups got: ")
                 .append(ca.privileges.toString())
                 .append("'\n");
        }

        break getPrivileges;
      }

      // "authenticated" access set?
      if (authenticated) {
        ca.privileges = Ace.findMergedPrivilege(acl, cb, null,
                                                Ace.whoTypeAuthenticated);
      }

      if (ca.privileges != null) {
        if (logger.debug()) {
          debugsb.append("...For authenticated got: ")
                 .append(ca.privileges.toString())
                 .append("'\n");
        }

        break getPrivileges;
      }

      // "other" access set?
      ca.privileges = Ace.findMergedPrivilege(acl, cb, null, Ace.whoTypeOther);

      if (ca.privileges == null) {
        // All might be available
        ca.privileges = Ace.findMergedPrivilege(acl, cb, null, Ace.whoTypeAll);
      }

      if (logger.debug()) {
        if (ca.privileges != null) {
          debugsb.append("...For other got: ")
                 .append(ca.privileges.toString())
                 .append("'\n");
        } else {
          debugsb.append("...For other got: NULL\n");
        }
      }
    } // getPrivileges

    if (isOwner) {
      // Owner always has read/write acl privilege

      final char racl = ca.privileges.getPrivilege(privReadAcl);
      final char wacl = ca.privileges.getPrivilege(privWriteAcl);

      if (((racl != allowed) && (racl != allowedInherited)) ||
              ((wacl != allowed) && (wacl != allowedInherited))) {
        ca.privileges = PrivilegeSet.mergePrivileges(ca.privileges,
                                                     PrivilegeSet.ownerAclPrivileges,
                                                     false);
      }
    }

    if (ca.privileges == null) {
      if (logger.debug()) {
        logger.debug(debugsb + "...Check access denied (noprivs)");
      }
      return ca;
    }

    ca.privileges = PrivilegeSet.setUnspecified(ca.privileges, isOwner);

    if (filter != null) {
      ca.privileges = PrivilegeSet.filterPrivileges(ca.privileges, filter);
    }

    if (usePool) {
      ca.privileges = privSets.get(ca.privileges);
    }

    if (how.length == 0) {
      // Means any access will do

      ca.accessAllowed = ca.privileges.getAnyAllowed();
      if (logger.debug()) {
        if (ca.accessAllowed) {
          logger.debug(debugsb +
                               "...Check access allowed (any requested)");
        } else {
          logger.debug(debugsb +
                                "...Check access denied (any requested)");
        }
      }

      return ca;
    }

    /* Check each requested access right. If denied, fail immediately, otherwise
     * continue to the next request right.
     */

    for (final Privilege privilege: how) {
      final char priv = ca.privileges.getPrivilege(privilege.getIndex());

      if ((priv != allowed) && (priv != allowedInherited)) {
        if (logger.debug()) {
          debugsb.append("...Check access denied (!allowed) ")
                 .append(ca.privileges.toString());
          logger.debug(debugsb.toString());
        }
        return ca;
      }
    }

    /* Caller specified some access rights they wanted and all of them are
     * granted.
     */

    if (logger.debug()) {
      logger.debug(debugsb + "...Check access allowed");
    }

    ca.accessAllowed = true;
    return ca;
  }
}
