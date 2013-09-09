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

import java.io.Serializable;

/** Some privilege definitions.
 *
 *  @author Mike Douglass   douglm@bedework.edu
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

  /* ----------------- CalDAV Scheduling ------------------------ */

  /** CalDAV schedule access
   */
  public static final int privScheduleDeliver = 16;

  /** CalDAV schedule access
   */
  public static final int privScheduleDeliverInvite = 17;

  /** CalDAV schedule access
   */
  public static final int privScheduleDeliverReply = 18;

  /** CalDAV schedule access
   */
  public static final int privScheduleQueryFreebusy = 19;

  /** CalDAV schedule access
   */
  public static final int privScheduleSend = 20;

  /** CalDAV schedule access
   */
  public static final int privScheduleSendInvite = 21;

  /** CalDAV schedule access
   */
  public static final int privScheduleSendReply = 22;

  /** CalDAV schedule access
   */
  public static final int privScheduleSendFreebusy = 23;

  /** Deny all access */
  public static final int privNone = 24;

  /** Max access index
   */
  public static final int privMaxType = 24;

  /** Indicate any allowed access will do
   */
  public static final int privAny = privMaxType + 1;


  /* !!!!!!!!!!!!!!!!!! need default access - i.e. remove any mention of who
   */

  /** Single char encoding
   * BCGHJKLMOVXYZ
   * dfghjklmnovwxz
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

    'D',     // privScheduleDeliver
    'i',     // privScheduleDeliverInvite
    'e',     // privScheduleDeliverReply
    'q',     // privScheduleQueryFreebusy

    'T',     // privScheduleSend
    'I',     // privScheduleSendInvite
    'E',     // privScheduleSendReply
    'Q',     // privScheduleSendFreebusy

    'N',     // privNone
  };
}
