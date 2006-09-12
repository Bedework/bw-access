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

import java.io.Serializable;

/** Some privilege definitions.
 *
 *  @author Mike Douglass   douglm@rpi.edu
 */
public interface PrivilegeDefs extends Serializable {
  /* old allowed and old denied allow us to respecify the flags allowing for
   * inherited access
   */
  /** Old allowed flag - appears in old acls being converted to new form
   */
  public static final char oldAllowed = '3';

  /** Old denied privilege.
   */
  public static final char oldDenied = '2';

  /* The following flags must sort with values in the order:
   * allowed, denied, allowedInherited, deniedInherited, unspecified.
   */

  /** Allowed flag - appears in acls
   */
  public static final char allowed = 'y';

  /** A denied privilege is a privilege, e.g. read which is denied to the
     associated 'who' - appears in ace.
   */
  public static final char denied = 'n';

  /** This only appears in the final result from Privileges.fromEncoding
   */
  public static final char allowedInherited = 'Y';

  /** This only appears in the final result from Privileges.fromEncoding
   */
  public static final char deniedInherited = 'N';

  /** This only appears in the final result from Privileges.fromEncoding
   */
  public static final char unspecified = '?';

  /** Shows an ace was inherited - appears in ace
   */
  public static final char inheritedFlag = 'I';

  // ENUM
  /** Define a privilege type index
   */

  /** All access
   */
  public static final int privAll = 0;

  /** Read access
   */
  public static final int privRead = 1;

  /** Read acl access
   */
  public static final int privReadAcl = 2;

  /** read current user privs access
   */
  public static final int privReadCurrentUserPrivilegeSet = 3;

  /** Read free busy access
   */
  public static final int privReadFreeBusy = 4;

  /** Write access
   */
  public static final int privWrite = 5;

  /** Write acl access
   */
  public static final int privWriteAcl = 6;

  /** Write properties access
   */
  public static final int privWriteProperties = 7;

  /** Write content (change) access
   */
  public static final int privWriteContent = 8;

  /** Bind (create) access
   */
  public static final int privBind = 9;

  /** CalDAV schedule access
   */
  public static final int privSchedule = 10;

  /** CalDAV schedule-request access
   */
  public static final int privScheduleRequest = 11;

  /** CalDAV schedule-reply access
   */
  public static final int privScheduleReply = 12;

  /** CalDAV schedule-free-busy access
   */
  public static final int privScheduleFreeBusy = 13;

  /** Unbind (destroy) access
   */
  public static final int privUnbind = 14;

  /** Unlock access
   */
  public static final int privUnlock = 15;

  /** Deny all access - used frequently? */
  public static final int privNone = 16;

  /** Max access index
   */
  public static final int privMaxType = 16;

  /** Indicate any allowed access will do
   */
  public static final int privAny = privMaxType + 1;


  /* !!!!!!!!!!!!!!!!!! need default access - i.e. remove any mention of who
   */

  /** Single char encoding
   */
  public final static char[] privEncoding = {
    'A',     // privAll

    'R',     // privRead
    'r',     // privReadAcl
    'P',     // privReadCurrentUserPrivilegeSet
    'F',     // privReadFreeBusy

    'W',     // privWrite
    'a',     // privWriteAcl
    'p',     // privWriteProperties
    'c',     // privWriteContent
    'b',     // privBind

    'S',     // privSchedule
    't',     // privScheduleRequest
    'y',     // privScheduleReply
    's',     // privScheduleFreeBusy

    'u',     // privUnbind
             // unbind and bind usually correspond to create and destroy

    'U',     // privUnlock
             // not implemented

    'N',     // privNone
  };
}
