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
 *      |      |      |  Below is old draft 6 CalDAV scheduling
 *      |      |      +-- [CALDAV:schedule} 'S'
 *      |      |             |
 *      |      |             +-- [CALDAV:schedule-request] 't'
 *      |      |             +-- [CALDAV:schedule-reply]   'y'
 *      |      |             +-- [CALDAV:schedule-free-busy] 's'
 *      |      |
 *      |      +-- [DAV: unbind] 'u'
 *      |
 *      +-- [DAV: unlock] 'U'
 *      |
 *      |  Below is after Draft 6
 *      +-- [CALDAV:schedule-deliver] (aggregate)
 *      |      |
 *      |      +-- [CALDAV:schedule-deliver-invite]
 *      |      +-- [CALDAV:schedule-deliver-reply]
 *      |      +-- [CALDAV:schedule-query-freebusy]
 *      |
 *      +-- [CALDAV:schedule-send] (aggregate)
 *             |
 *             +-- [CALDAV:schedule-send-invite]
 *             +-- [CALDAV:schedule-send-reply]
 *             +-- [CALDAV:schedule-send-freebusy]
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

    /*
    for (Privilege p: privs) {
      System.out.println(p);
    }
    for (Privilege p: deniedPrivs) {
      System.out.println(p);
    }
    */
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
    return privs[privType];
  }

  /** make a privilege defining the given priv type
   *
   * @param privType int access
   * @param  denial   true for a denial
   * @return Privilege defining access
   */
  public static Privilege makePriv(int privType, boolean denial) {
    if (!denial) {
      return privs[privType];
    }
    return deniedPrivs[privType];
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

  private static void makePrivileges(Privilege[] ps,
                                     boolean denial) {
    /* ---------------- read privileges ----------------------- */

    ps[privReadAcl] = new Privilege("read-acl", "Read calendar accls",
                                    denial, privReadAcl);

    ps[privReadCurrentUserPrivilegeSet] =
      new Privilege("read-current-user-privilege-set",
                    "Read current user privilege set property",
                    denial, privReadCurrentUserPrivilegeSet);

    ps[privReadFreeBusy] = new Privilege("view-free-busy",
                                         "View a users free busy information",
                                         denial, privReadFreeBusy);

    Privilege[] containedRead = {ps[privReadAcl],
                                 ps[privReadCurrentUserPrivilegeSet],
                                 ps[privReadFreeBusy]};
    ps[privRead] = new Privilege("read", "Read any calendar object", denial,
                                 privRead, containedRead);

    /* -------------- schedule (draft 6) privileges -------------- */

    ps[privScheduleRequest] = new Privilege("schedule-request",
                                            "Submit schedule request",
                                            denial, privScheduleRequest);

    ps[privScheduleReply] = new Privilege("schedule-reply",
                                          "Submit schedule reply",
                                          denial, privScheduleReply);

    ps[privScheduleFreeBusy] = new Privilege("schedule-free-busy",
                                             "Freebusy for scheduling",
                                             denial, privScheduleFreeBusy);

    Privilege[] containedSchedule = {ps[privScheduleRequest],
                                     ps[privScheduleReply],
                                     ps[privScheduleFreeBusy]};
    ps[privSchedule] = new Privilege("schedule", "Scheduling operations",
                                     denial, privSchedule,
                                     containedSchedule);

    /* ---------------- bind privileges ----------------------- */

    Privilege[] containedBind = {ps[privSchedule]};
    ps[privBind] = new Privilege("create", "Create a calendar object",
                                 denial, privBind, containedBind);

    /* ---------------- write privileges ----------------------- */

    ps[privWriteAcl] = new Privilege("write-acl", "Write ACL", denial,
                                     privWriteAcl);

    ps[privWriteProperties] = new Privilege("write-properties",
                                            "Write calendar properties",
                                            denial, privWriteProperties);

    ps[privWriteContent] = new Privilege("write-content",
                                         "Write calendar content",
                                         denial, privWriteContent);

    ps[privUnbind] = new Privilege("delete", "Delete a calendar object",
                                   denial, privUnbind);

    Privilege[] containedWrite = {ps[privWriteAcl],
                                  ps[privWriteProperties],
                                  ps[privWriteContent],
                                  ps[privBind],
                                  ps[privUnbind]};
    ps[privWrite] = new Privilege("write", "Write any calendar object",
                                  denial, privWrite,
                                  containedWrite);

    /* ---------------- schedule deliver privileges ----------------------- */

    ps[privScheduleDeliverInvite] = new Privilege("schedule-deliver-invite",
                                                  "Schedule: deliver invitations",
                                                  denial,
                                                  privScheduleDeliverInvite);

    ps[privScheduleDeliverReply] = new Privilege("schedule-deliver-reply",
                                                  "Schedule: deliver replies",
                                                  denial,
                                                  privScheduleDeliverReply);

    ps[privScheduleQueryFreebusy] = new Privilege("schedule-query-freebusy",
                                                  "Schedule: query freebusy",
                                                  denial,
                                                  privScheduleQueryFreebusy);

    Privilege[] containedScheduleDeliver = {ps[privScheduleDeliverInvite],
                                            ps[privScheduleDeliverReply],
                                            ps[privScheduleQueryFreebusy]};
    ps[privScheduleDeliver] = new Privilege("schedule-deliver",
                                            "Scheduling delivery",
                                            denial,
                                            privScheduleDeliver,
                                            containedScheduleDeliver);

    /* ---------------- schedule send privileges ----------------------- */

    ps[privScheduleSendInvite] = new Privilege("schedule-send-invite",
                                               "Schedule: send invitations",
                                               denial,
                                               privScheduleSendInvite);

    ps[privScheduleSendReply] = new Privilege("schedule-send-reply",
                                              "Schedule: send replies",
                                              denial,
                                              privScheduleSendReply);

    ps[privScheduleSendFreebusy] = new Privilege("schedule-send-freebusy",
                                                 "Schedule: send freebusy",
                                                 denial,
                                                 privScheduleSendFreebusy);

    Privilege[] containedScheduleSend = {ps[privScheduleSendInvite],
                                         ps[privScheduleSendReply],
                                         ps[privScheduleSendFreebusy]};
    ps[privScheduleSend] = new Privilege("schedule-send",
                                         "Scheduling send",
                                         denial,
                                         privScheduleSend,
                                         containedScheduleSend);

    /* ---------------- all privileges ----------------------- */

    ps[privUnlock] = new Privilege("unlock", "Remove a lock",
                                   denial, privUnlock);

    Privilege[] containedAll = {ps[privRead],
                                ps[privWrite],
                                ps[privUnlock],
                                ps[privScheduleDeliver],
                                ps[privScheduleSend]};
    ps[privAll] = new Privilege("all", "All privileges", denial, privAll,
                                containedAll);

    ps[privNone] = Privilege.cloneDenied(ps[privAll]);
  }
}

