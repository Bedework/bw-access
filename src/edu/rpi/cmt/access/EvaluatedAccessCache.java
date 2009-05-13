/* **********************************************************************
    Copyright 2006 Rensselaer Polytechnic Institute. All worldwide rights reserved.

    Redistribution and use of this distribution in source and binary forms,
    with or without modification, are permitted provided that:
       The above copyright notice and this permission notice appear in all
        copies and supporting documentation;

        The name, identifiers, and trademarks of Rensselaer Polytechnic
        Institute are not used in advertising or publicity without the
        express prior written permission of Rensselaer Polytechnic Institute;

    DISCLAIMER: The software is distributed" AS IS" without any express or
    implied warranty, including but not limited to, any implied warranties
    of merchantability or fitness for a particular purpose or any warrant)'
    of non-infringement of any current or pending patent rights. The authors
    of the software make no representations about the suitability of this
    software for any particular purpose. The entire risk as to the quality
    and performance of the software is with the user. Should the software
    prove defective, the user assumes the cost of all necessary servicing,
    repair or correction. In particular, neither Rensselaer Polytechnic
    Institute, nor the authors of the software are liable for any indirect,
    special, consequential, or incidental damages related to the software,
    to the maximum extent the law permits.
*/
package edu.rpi.cmt.access;

import edu.rpi.cmt.access.Acl.CurrentAccess;

import org.apache.log4j.Logger;

import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/** This provides a cache of evaluated CurrentAccess objects. Rather than create
 * a composite key, which itself involves creating a new object per search, we
 * instead creae  hierarchical set of tables, each indexed by an element of the
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
  private transient Logger log;

  private Map<String, Map> ownerHrefs = new HashMap<String, Map>();

  /* Back end of the queue is the most recently referenced. */
  private LinkedList<String> accessorQueue = new LinkedList<String>();

  /**
   * @param ownerHref
   * @param accessorHref
   * @param desiredPriv
   * @param maxAccess
   * @param acl
   * @return CurrentAccess or null
   */
  public CurrentAccess get(String ownerHref,
                           String accessorHref,
                           int desiredPriv,   // XXX should be a privilege set
                           PrivilegeSet maxAccess,
                           String acl) {
    Map<String, Map> accessors = ownerHrefs.get(ownerHref);

    if (accessors == null) {
      return null;
    }

    /* ===================== desired priv ================== */

    Map<Integer, Map> desiredPrivs = accessors.get(accessorHref);

    if (desiredPrivs == null) {
      return null;
    }

    accessorQueue.remove(accessorHref);
    accessorQueue.add(accessorHref);

    /* ===================== max priv ================== */

    Map<PrivilegeSet, Map> maxPrivs = desiredPrivs.get(desiredPriv);

    if (maxPrivs == null) {
      return null;
    }

    /* ===================== acl ================== */

    Map<String, CurrentAccess> acls = maxPrivs.get(maxAccess);

    if (acls == null) {
      return null;
    }

    /* ==================== finally access =============== */

    return acls.get(acl);
  }

  /**
   * @param ownerHref
   * @param accessorHref
   * @param desiredPriv
   * @param maxAccess
   * @param acl
   * @param ca
   */
  public void put(String ownerHref,
                  String accessorHref,
                  int desiredPriv,   // XXX should be a privilege set
                  PrivilegeSet maxAccess,
                  String acl,
                  CurrentAccess ca) {
    boolean found = true;

    Map<String, Map> accessors = ownerHrefs.get(ownerHref);

    if (accessors == null) {
      accessors = new HashMap<String, Map>();
      ownerHrefs.put(ownerHref, accessors);
      found = false;
    }

    accessorQueue.remove(accessorHref);
    accessorQueue.add(accessorHref);

    /* ===================== desired priv ================== */

    Map<Integer, Map> desiredPrivs = null;
    if (found) {
      // Try a search
      desiredPrivs = accessors.get(accessorHref);
    }

    if (desiredPrivs == null) {
      desiredPrivs = new HashMap<Integer, Map>();
      accessors.put(accessorHref, desiredPrivs);
      found = false;
    }

    /* ===================== max priv ================== */

    Map<PrivilegeSet, Map> maxPrivs = null;
    if (found) {
      // Try a search
      maxPrivs = desiredPrivs.get(desiredPriv);
    }

    if (maxPrivs == null) {
      maxPrivs = new HashMap<PrivilegeSet, Map>();
      desiredPrivs.put(desiredPriv, maxPrivs);
      found = false;
    }

    /* ===================== acl ================== */

    Map<String, CurrentAccess> acls = null;
    if (found) {
      // Try a search
      acls = maxPrivs.get(maxAccess);
    }

    if (acls == null) {
      acls = new HashMap<String, CurrentAccess>();
      maxPrivs.put(maxAccess, acls);
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

    acls.put(acl, ca);
  }

  private Logger getLog() {
    if (log == null) {
      log = Logger.getLogger(getClass());
    }

    return log;
  }

  private void error(String msg) {
    getLog().error(msg);
  }
  }
