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

import edu.rpi.sss.util.ObjectPool;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

/** Allowed privileges for a principal
 *
 *  @author Mike Douglass   douglm@rpi.edu
 */
public class PrivilegeSet implements Serializable, PrivilegeDefs, Comparable {
  private char[] privileges;

  private static ObjectPool<PrivilegeSet> privSets = new ObjectPool<PrivilegeSet>();

  private static boolean usePool = true;

  /** Default privs for an owner
   */
  public static PrivilegeSet defaultOwnerPrivileges =
    pooled(new PrivilegeSet(allowed,   // privAll
                     allowed,   // privRead
                     allowed,   // privReadAcl
                     allowed,   // privReadCurrentUserPrivilegeSet
                     allowed,   // privReadFreeBusy
                     allowed,   // privWrite
                     allowed,   // privWriteAcl
                     allowed,   // privWriteProperties
                     allowed,   // privWriteContent
                     allowed,   // privBind
                     allowed,   // privSchedule
                     allowed,   // privScheduleRequest
                     allowed,   // privScheduleReply
                     allowed,   // privScheduleFreeBusy
                     allowed,   // privUnbind
                     allowed,   // privUnlock
                     allowed));   // privNone

  /** User home max privileges for non-super user
   * This allows us to turn off privileges which would allow delete or rename
   * for example.
   */
  public static PrivilegeSet userHomeMaxPrivileges =
    pooled(new PrivilegeSet(denied,   // privAll
                     allowed,   // privRead
                     allowed,   // privReadAcl
                     allowed,   // privReadCurrentUserPrivilegeSet
                     allowed,   // privReadFreeBusy
                     denied,   // privWrite
                     allowed,   // privWriteAcl
                     allowed,   // privWriteProperties
                     allowed,   // privWriteContent
                     denied,   // privBind
                     denied,   // privSchedule
                     denied,   // privScheduleRequest
                     denied,   // privScheduleReply
                     denied,   // privScheduleFreeBusy
                     denied,   // privUnbind
                     allowed,   // privUnlock
                     allowed));   // privNone

  /** Default privs for a non owner
   */
  public static PrivilegeSet defaultNonOwnerPrivileges =
    pooled(new PrivilegeSet(denied,   // privAll
                     denied,   // privRead
                     denied,   // privReadAcl
                     denied,   // privReadCurrentUserPrivilegeSet
                     denied,   // privReadFreeBusy
                     denied,   // privWrite
                     denied,   // privWriteAcl
                     denied,   // privWriteProperties
                     denied,   // privWriteContent
                     denied,   // privBind
                     denied,   // privSchedule
                     denied,   // privScheduleRequest
                     denied,   // privScheduleReply
                     denied,   // privScheduleFreeBusy
                     denied,   // privUnbind
                     denied,   // privUnlock
                     denied));   // privNone

  /**
   * @param privAllState
   * @param privReadState
   * @param privReadAclState
   * @param privReadCurrentUserPrivilegeSetState
   * @param privReadFreeBusyState
   * @param privWriteState
   * @param privWriteAclState
   * @param privWritePropertiesState
   * @param privWriteContentState
   * @param privBindState
   * @param privScheduleState
   * @param privScheduleRequestState
   * @param privScheduleReplyState
   * @param privScheduleFreeBusyState
   * @param privUnbindState
   * @param privUnlockState
   * @param privNoneState
   */
  public PrivilegeSet(char privAllState,
                      char privReadState,
                      char privReadAclState,
                      char privReadCurrentUserPrivilegeSetState,
                      char privReadFreeBusyState,
                      char privWriteState,
                      char privWriteAclState,
                      char privWritePropertiesState,
                      char privWriteContentState,
                      char privBindState,
                      char privScheduleState,
                      char privScheduleRequestState,
                      char privScheduleReplyState,
                      char privScheduleFreeBusyState,
                      char privUnbindState,
                      char privUnlockState,
                      char privNoneState) {
    privileges = new char[privMaxType + 1];

    privileges[privAll] = privAllState;
    privileges[privRead] = privReadState;
    privileges[privReadAcl] = privReadAclState;
    privileges[privReadCurrentUserPrivilegeSet] = privReadCurrentUserPrivilegeSetState;
    privileges[privReadFreeBusy] = privReadFreeBusyState;
    privileges[privWrite] = privWriteState;
    privileges[privWriteAcl] = privWriteAclState;
    privileges[privWriteProperties] = privWritePropertiesState;
    privileges[privWriteContent] = privWriteContentState;
    privileges[privBind] = privBindState;
    privileges[privSchedule] = privScheduleState;
    privileges[privScheduleRequest] = privScheduleRequestState;
    privileges[privScheduleReply] = privScheduleReplyState;
    privileges[privScheduleFreeBusy] = privScheduleFreeBusyState;
    privileges[privUnbind] = privUnbindState;
    privileges[privUnlock] = privUnlockState;
    privileges[privNone] = privNoneState;
  }

  /**
   * @param privileges
   */
  public PrivilegeSet(char[] privileges) {
    this.privileges = privileges;
  }

  /**
   */
  public PrivilegeSet() {
    privileges = defaultNonOwnerPrivileges.getPrivileges();
  }

  /** Default privs for an owner
   *
   * @return PrivilegeSet
   */
  public static PrivilegeSet makeDefaultOwnerPrivileges() {
    return defaultOwnerPrivileges;
    //return pooled((PrivilegeSet)defaultOwnerPrivileges.clone());
  }

  /** User home max privileges for non-super user
   * This allows us to turn off privileges which would allow delete or rename
   * for example.
   *
   * @return PrivilegeSet
   */
  public static PrivilegeSet makeUserHomeMaxPrivileges() {
    return userHomeMaxPrivileges;
    //return pooled((PrivilegeSet)userHomeMaxPrivileges.clone());
  }

  /** Default privs for a non owner
   *
   * @return PrivilegeSet
   */
  public static PrivilegeSet makeDefaultNonOwnerPrivileges() {
    return defaultNonOwnerPrivileges;
    //return pooled((PrivilegeSet)defaultNonOwnerPrivileges.clone());
  }

  /** Make a privilege set from the given privilege
   *
   * @param priv  Privilege object
   * @return PrivilegeSet
   */
  public static PrivilegeSet makePrivileges(Privilege priv) {
    PrivilegeSet pset = new PrivilegeSet();

    pset.privileges = new char[privMaxType + 1];

    if (priv.getDenial()) {
      pset.privileges[priv.getIndex()] = denied;
    } else {
      pset.privileges[priv.getIndex()] = allowed;
    }

    /* Iterate over the children */

    for (Privilege p: priv.getContainedPrivileges()) {
      pset.setPrivilege(p);
    }

    return pooled(pset);
  }

  /** Returns a set of flags indicating if the indexed privilege (see above
   * for index) is allowed, denied or unspecified.
   *
   * @param acl
   * @return char[] access flags
   * @throws AccessException
   */
  public static PrivilegeSet fromEncoding(EncodedAcl acl) throws AccessException {
    char[] privStates = {
      unspecified,   // privAll
      unspecified,   // privRead
      unspecified,   // privReadAcl
      unspecified,   // privReadCurrentUserPrivilegeSet
      unspecified,   // privReadFreeBusy
      unspecified,   // privWrite
      unspecified,   // privWriteAcl
      unspecified,   // privWriteProperties
      unspecified,   // privWriteContent
      unspecified,   // privBind
      unspecified,   // privSchedule
      unspecified,   // privScheduleRequest
      unspecified,   // privScheduleReply
      unspecified,   // privScheduleFreeBusy
      unspecified,   // privUnbind
      unspecified,   // privUnlock
      unspecified,   // privNone
    };

    while (acl.hasMore()) {
      char c = acl.getChar();
      if ((c == ' ') || (c == inheritedFlag)) {
        break;
      }
      acl.back();

      Privilege p = Privilege.findPriv(Privileges.getPrivAll(),
                                       Privileges.getPrivNone(), acl);
      if (p == null) {
        throw AccessException.badACL("unknown priv " + acl.getErrorInfo());
      }

      //System.out.println("found " + p);\

      // Set the states based on the priv we just found.
      setState(privStates, p, p.getDenial());
    }

    return pooled(new PrivilegeSet(privStates));
  }

  /** Add the given privilege
   *
   * @param pset PrivilegeSet to add priv to
   * @param priv  Privilege object
   * @return PrivilegeSet
   */
  public static PrivilegeSet addPrivilege(PrivilegeSet pset,
                                          Privilege priv) {
    PrivilegeSet newPset = (PrivilegeSet)pset.clone();

    if (newPset.privileges == null) {
      newPset.privileges = defaultNonOwnerPrivileges.getPrivileges();
    }

    if (priv.getDenial()) {
      newPset.privileges[priv.getIndex()] = denied;
    } else {
      newPset.privileges[priv.getIndex()] = allowed;
    }

    /* Iterate over the children */

    for (Privilege p: priv.getContainedPrivileges()) {
      newPset.setPrivilege(p);
    }

    return pooled(newPset);
  }

  /** Get the given privilege
   *
   * @param index
   * @return char
   */
  public char getPrivilege(int index) {
    if (privileges == null) {
      return unspecified;
    }

    return privileges[index];
  }

  /** Ensure this privilegeset has no privilege greater than those in the filter
   *
   * @param pset PrivilegeSet to filter
   * @param filter
   * @return PrivilegeSet
   */
  public static PrivilegeSet filterPrivileges(PrivilegeSet pset,
                                              PrivilegeSet filter) {
    PrivilegeSet newPset = (PrivilegeSet)pset.clone();

    if (newPset.privileges == null) {
      newPset.privileges = defaultNonOwnerPrivileges.getPrivileges();
    }

    char[] filterPrivs = filter.privileges;

    for (int pi = 0; pi < newPset.privileges.length; pi++) {
      if (newPset.privileges[pi] > filterPrivs[pi]) {
        newPset.privileges[pi] = filterPrivs[pi];
      }
    }

    return pooled(newPset);
  }

  /** Return true if there is any allowed access
   *
   * @return boolean
   */
  public boolean getAnyAllowed() {
    if (privileges == null) {
      return false;
    }

    for (int pi = 0; pi < privileges.length; pi++) {
      char pr = privileges[pi];

      if (pr == allowed) {
        return true;
      }

      if (pr == allowedInherited) {
        return true;
      }
    }

    return false;
  }

  /** If current is null it is set to a cloned copy of morePriv otherwise the
   * privilege(s) in morePriv are merged into current.
   *
   * <p>Specified access overrides inherited access,<br/>
   * allowed overrides denied overrides unspecified so the order is, from
   * highest to lowest:<br/>
   *
   * allowed, denied, allowedInherited, deniedInherited, unspecified.
   *
   * <p>Only allowed and denied appear in encoded aces.
   *
   * @param current
   * @param morePriv
   * @param inherited   true if the ace was an inherited ace
   * @return PrivilegeSet  mergedPrivileges
   */
  public static PrivilegeSet mergePrivileges(PrivilegeSet current,
                                             PrivilegeSet morePriv,
                                             boolean inherited) {
    PrivilegeSet mp = (PrivilegeSet)morePriv.clone();

    if (inherited) {
      for (int i = 0; i <= privMaxType; i++) {
        char p = mp.getPrivilege(i);
        if (p == allowed) {
          mp.setPrivilege(i, allowedInherited);
        } else if (p == denied) {
          mp.setPrivilege(i, deniedInherited);
        }
      }
    }

    if (current == null) {
      return mp;
    }

    for (int i = 0; i <= privMaxType; i++) {
      char priv = mp.getPrivilege(i);
      if (current.getPrivilege(i) < priv) {
        current.setPrivilege(i, priv);
      }
    }

    return pooled(current);
  }

  /** Set all unspecified values to allowed for the owner or denied otherwise.
   *
   * @param pset
   * @param isOwner
   * @return PrivilegeSet
   */
  public static PrivilegeSet setUnspecified(PrivilegeSet pset,
                                            boolean isOwner) {
    PrivilegeSet newPset = (PrivilegeSet)pset.clone();

    if (newPset.privileges == null) {
      newPset.privileges = defaultNonOwnerPrivileges.getPrivileges();
    }

    for (int pi = 0; pi < newPset.privileges.length; pi++) {
      if (newPset.privileges[pi] == unspecified) {
        if (isOwner) {
          newPset.privileges[pi] = allowed;
        } else {
          newPset.privileges[pi] = denied;
        }
      }
    }

    return pooled(newPset);
  }

  /**
   * @return char[]  privileges for this object
   */
  public char[] getPrivileges() {
    if (privileges == null) {
      return null;
    }
    return (char[])privileges.clone();
  }

  /** Return list of Privilege once we have removed all included Privileges
   *
   * @return privs
   */
  public Collection<Privilege> getPrivs() {
    char[] ps = getPrivileges();

    /* First reset all privs that are included by others
     */
    for (int pi = 0; pi < ps.length; pi++) {
      if (ps[pi] != unspecified) {
        Privilege priv = Privileges.makePriv(pi);

        for (Privilege pr: priv.getContainedPrivileges()) {
          setUnspec(ps, pr);
        }
      }
    }

    /* Now return the collection */
    Collection<Privilege> privs = new ArrayList<Privilege>();

    for (int pi = 0; pi < ps.length; pi++) {
      if (ps[pi] != unspecified) {
        privs.add(Privileges.makePriv(pi));
      }
    }

    return privs;
  }

  private void setUnspec(char[] ps, Privilege priv) {
    ps[priv.getIndex()] = unspecified;

    for (Privilege pr: priv.getContainedPrivileges()) {
      setUnspec(ps, pr);
    }

  }

  /* ====================================================================
   *                   Private methods
   * ==================================================================== */

  private static PrivilegeSet pooled(PrivilegeSet val) {
    if (!usePool) {
      return val;
    }

    return privSets.get(val);
  }

  /** Set the given privilege
   *
   * @param index
   * @param val
   */
  private void setPrivilege(int index, char val) {
    if (privileges == null) {
      privileges = defaultNonOwnerPrivileges.getPrivileges();
    }

    privileges[index] = val;
  }

  /** Set the given privilege
   *
   * @param priv  Privilege object
   */
  private void setPrivilege(Privilege priv) {
    if (privileges == null) {
      privileges = defaultNonOwnerPrivileges.getPrivileges();
    }

    if (priv.getDenial()) {
      privileges[priv.getIndex()] = denied;
    } else {
      privileges[priv.getIndex()] = allowed;
    }

    /* Iterate over the children */

    for (Privilege p: priv.getContainedPrivileges()) {
      setPrivilege(p);
    }
  }

  /* As an example, say we are setting read access. From above:
   *      +-- [DAV: read] 'R'
   *      |      |
   *      |      +-- [DAV: read-acl]  'r'
   *      |      +-- [DAV: read-current-user-privilege-set] 'P'
   *      |      +-- [CALDAV:view-free-busy] 'F'
   *
   *  That is, read includes read-acl, read-current-user-privilege-set and
   *  view-free-busy.
   *
   *  So for this we set allowed or denied in the states array for each of those
   *  privileges.
   */
  private static void setState(char[] states, Privilege p, boolean denial) {
    // XXX Should we only set either way of the access is unspecified?
    if (!denial) {
      states[p.getIndex()] = allowed;
//    } else {
    } else if (states[p.getIndex()] == unspecified) {
      states[p.getIndex()] = denied;
    }

    /* Iterate over the children */

    for (Privilege pr: p.getContainedPrivileges()) {
      setState(states, pr, denial);
    }
  }

  /* ====================================================================
   *                   Object methods
   * ==================================================================== */

  public int compareTo(Object o) {
    if (this == o) {
      return 0;
    }

    if (!(o instanceof PrivilegeSet)) {
      return 1;
    }

    PrivilegeSet that = (PrivilegeSet)o;
    if (privileges == null) {
      if (that.privileges != null) {
        return -1;
      }

      return 0;
    }

    if (that.privileges == null) {
      return 1;
    }

    for (int pi = 0; pi < privileges.length; pi++) {
      char thisp = privileges[pi];
      char thatp = that.privileges[pi];

      if (thisp < thatp) {
        return -1;
      }

      if (thisp > thatp) {
        return -1;
      }
    }

    return 0;
  }

  public int hashCode() {
    int hc = 7;

    if (privileges == null) {
      return hc;
    }

    for (int pi = 0; pi < privileges.length; pi++) {
      hc *= privileges[pi];
    }

    return hc;
  }

  public boolean equals(Object o) {
    return compareTo(o) == 0;
  }

  public Object clone() {
    return new PrivilegeSet(getPrivileges());
  }

  public String toString() {
    StringBuffer sb = new StringBuffer("PrivilegeSet[");

    sb.append(privileges);
    sb.append("]");

    return sb.toString();
  }
}
