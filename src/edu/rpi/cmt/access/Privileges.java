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

import java.util.ArrayList;
import java.util.Collection;

/** Define the privileges we recognize for the calendar.
 *
 * <p>These are based on webdav + caldav privileges and are flagged below as
 * W for webdav and C for caldav
 *
 * <p>Ideally we will initialise this once per session and reuse the objects
 * during processing.
 *
 * <p>Webdav access control defines privileges in terms of a tree of rights.
 *  Here we define that tree (based on the RFC3744 description]).
 *  <pre>
 *   [DAV: all]  'A'
 *      |
 *      +-- [DAV: read] 'R'
 *      |      |
 *      |      +-- [DAV: read-acl]  'r'
 *      |      +-- [DAV: read-current-user-privilege-set] 'P'
 *      |      +-- [CALDAV:view-free-busy] 'F'
 *      |
 *      +-- [DAV: write] 'W'
 *      |      |
 *      |      +-- [DAV: write-acl] 'a'
 *      |      +-- [DAV: write-properties] 'p'
 *      |      +-- [DAV: write-content] 'c'
 *      |      +-- [DAV: bind] 'b'
 *      |      |      |
 *      |      |      +-- [CALDAV:schedule} 'S'
 *      |      |             |
 *      |      |             +-- [CALDAV:schedule-request] 't'
 *      |      |             +-- [CALDAV:schedule-reply]   'y'
 *      |      |             +-- [CALDAV:schedule-free-busy] 's'
 *      |      |
 *      |      +-- [DAV: unbind] 'u'
 *      |
 *      +-- [DAV: unlock] 'U'
 *      </pre>
 *   <p>encode the acl as a character sequence. Privileges within that sequence
 *   are flagged by the characters above. The sequence of privileges is terminated
 *   by a blank, e.g <ul>
 *            <li>"ARAW "   is read write</li>
 *            <li>"DW "   is write denied</li>
 *   </ul>
 *
 *   <p>We try not to expand acls but parse the character string to determine
 *   the allowed access. However, for acl manipulation which occurs much less
 *   frequently it is usually better to expand.
 *
 *  @author Mike Douglass   douglm@rpi.edu
 */
public class Privileges implements PrivilegeDefs {

  // ENUM - use EnumNap
  private final static Privilege[] privs = new Privilege[privMaxType + 1];
  private final static Privilege[] deniedPrivs = new Privilege[privMaxType + 1];

  static {
    makePrivileges(privs, false);
    makePrivileges(deniedPrivs, true);
  }

  /** Constructor
   *
   */
  private Privileges() {
  }

  /**
   * @return Privilege defining all access
   */
  public static Privilege getPrivAll() {
    return privs[privAll];
  }

  /**
   * @return Privilege defining no access
   */
  public static Privilege getPrivNone() {
    return privs[privNone];
  }

  /** make a privilege defining the given priv type
   *
   * @param privType int access
   * @return Privilege defining access
   */
  public static Privilege makePriv(int privType) {
    return /*(Privilege)*/privs[privType]/*.clone()*/;
  }

  /** make a privilege defining the given priv type
   *
   * @param privType int access
   * @param  denial   true for a denial
   * @return Privilege defining access
   */
  public static Privilege makePriv(int privType, boolean denial) {
    if (!denial) {
      return /*(Privilege)*/privs[privType]/*.clone()*/;
    }
    return /*(Privilege)*/deniedPrivs[privType]/*.clone()*/;
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

      Privilege p = Privilege.findPriv(privs[privAll], privs[privNone], acl);
      if (p == null) {
        throw AccessException.badACL("unknown priv " + acl.getErrorInfo());
      }

      //System.out.println("found " + p);\

      // Set the states based on the priv we just found.
      setState(privStates, p, p.getDenial());
    }

    return new PrivilegeSet(privStates);
  }

  /** Skip all the privileges info.
   *
   * @param acl
   * @throws AccessException
   */
  public static void skip(EncodedAcl acl) throws AccessException {
    while (acl.hasMore()) {
      char c = acl.getChar();
      if ((c == ' ') || (c == inheritedFlag)) {
        break;
      }
    }
  }

  /** Returns the collection of privilege objects representing the access.
   * Used for acl manipulation..
   *
   * @param acl
   * @return Collection
   * @throws AccessException
   */
  public static Collection<Privilege> getPrivs(EncodedAcl acl) throws AccessException {
    ArrayList<Privilege> al = new ArrayList<Privilege>();

    while (acl.hasMore()) {
      char c = acl.getChar();
      if ((c == ' ') || (c == inheritedFlag)) {
        break;
      }
      acl.back();

      Privilege p = Privilege.findPriv(privs[privAll], privs[privNone], acl);
      if (p == null) {
        throw AccessException.badACL("unknown priv");
      }

      al.add(p);
    }

    return al;
  }

  private static void setState(char[] states, Privilege p, boolean denial) {
    if (!denial) {
      states[p.getIndex()] = allowed;
    } else {
      states[p.getIndex()] = denied;
    }

    /* Iterate over the children */

    for (Privilege pr: p.getContainedPrivileges()) {
      setState(states, pr, denial);
    }
  }

  private static void makePrivileges(Privilege[] ps,
                                     boolean denial) {
    ps[privAll] = new Privilege("all", "All privileges", denial, privAll);

    ps[privRead] = new Privilege("read", "Read any calendar object", denial,
                                 privRead);

    ps[privReadAcl] = new Privilege("read-acl", "Read calendar accls",
                                    denial, privReadAcl);

    ps[privReadCurrentUserPrivilegeSet] =
      new Privilege("read-current-user-privilege-set",
                    "Read current user privilege set property",
                    denial, privReadCurrentUserPrivilegeSet);

    ps[privReadFreeBusy] = new Privilege("view-free-busy",
                                         "View a users free busy information",
                                         denial, privReadFreeBusy);

    ps[privWrite] = new Privilege("write", "Write any calendar object",
                                  denial, privWrite);

    ps[privWriteAcl] = new Privilege("write-acl", "Write ACL", denial,
                                     privWriteAcl);

    ps[privWriteProperties] = new Privilege("write-properties",
                                            "Write calendar properties",
                                            denial, privWriteProperties);

    ps[privWriteContent] = new Privilege("write-content",
                                         "Write calendar content",
                                         denial, privWriteContent);

    ps[privBind] = new Privilege("create", "Create a calendar object",
                                 denial, privBind);

    ps[privSchedule] = new Privilege("schedule", "Scheduling operations",
                                     denial, privSchedule);

    ps[privScheduleRequest] = new Privilege("schedule-request",
                                            "Submit schedule request",
                                            denial, privScheduleRequest);

    ps[privScheduleReply] = new Privilege("schedule-reply",
                                          "Submit schedule reply",
                                          denial, privScheduleReply);

    ps[privScheduleFreeBusy] = new Privilege("schedule-free-busy",
                                             "Freebusy for scheduling",
                                             denial, privScheduleFreeBusy);

    ps[privUnbind] = new Privilege("delete", "Delete a calendar object",
                                   denial, privUnbind);

    ps[privUnlock] = new Privilege("unlock", "Remove a lock",
                                   denial, privUnlock);

    ps[privAll].addContainedPrivilege(ps[privRead]);
    ps[privAll].addContainedPrivilege(ps[privWrite]);
    ps[privAll].addContainedPrivilege(ps[privUnlock]);

    ps[privRead].addContainedPrivilege(ps[privReadAcl]);
    ps[privRead].addContainedPrivilege(ps[privReadCurrentUserPrivilegeSet]);
    ps[privRead].addContainedPrivilege(ps[privReadFreeBusy]);

    ps[privWrite].addContainedPrivilege(ps[privWriteAcl]);
    ps[privWrite].addContainedPrivilege(ps[privWriteProperties]);
    ps[privWrite].addContainedPrivilege(ps[privWriteContent]);
    ps[privWrite].addContainedPrivilege(ps[privBind]);
    ps[privWrite].addContainedPrivilege(ps[privUnbind]);

    ps[privBind].addContainedPrivilege(ps[privSchedule]);

    ps[privSchedule].addContainedPrivilege(ps[privScheduleRequest]);
    ps[privSchedule].addContainedPrivilege(ps[privScheduleReply]);
    ps[privSchedule].addContainedPrivilege(ps[privScheduleFreeBusy]);

    ps[privNone] = Privilege.cloneDenied(ps[privAll]);
  }
}

