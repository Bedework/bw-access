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
 *  @author Mike Douglass   douglm@bedework.org
 */
public interface PrivilegeDefs extends Serializable {
  /* old allowed and old denied allow us to respecify the flags allowing for
   * inherited access
   */
  /** Old allowed flag - appears in old acls being converted to new form
   */
  char oldAllowed = '3';

  /** Old denied privilege.
   */
  char oldDenied = '2';

  /* The following flags must sort with values in the order:
   * allowed, denied, allowedInherited, deniedInherited, unspecified.
   */

  /** Allowed flag - appears in acls
   */
  char allowed = 'y';

  /** A denied privilege is a privilege, e.g. read which is denied to the
     associated 'who' - appears in ace.
   */
  char denied = 'n';

  /** This only appears in the final result from Privileges.fromEncoding
   */
  char allowedInherited = 'Y';

  /** This only appears in the final result from Privileges.fromEncoding
   */
  char deniedInherited = 'N';

  /** This only appears in the final result from Privileges.fromEncoding
   */
  char unspecified = '?';

  /** Shows an ace was inherited - appears in ace
   */
  char inheritedFlag = 'I';

  // ENUM
  /* Define a privilege type index
   */

  /** All access
   */
  int privAll = 0;

  /** Read access
   */
  int privRead = 1;

  /** Read acl access
   */
  int privReadAcl = 2;

  /** read current user privs access
   */
  int privReadCurrentUserPrivilegeSet = 3;

  /** Read free busy access
   */
  int privReadFreeBusy = 4;

  /** Write access
   */
  int privWrite = 5;

  /** Write acl access
   */
  int privWriteAcl = 6;

  /** Write properties access
   */
  int privWriteProperties = 7;

  /** Write content (change) access
   */
  int privWriteContent = 8;

  /** Bind (create) access
   */
  int privBind = 9;

  /** CalDAV schedule access
   */
  int privSchedule = 10;

  /** CalDAV schedule-request access
   */
  int privScheduleRequest = 11;

  /** CalDAV schedule-reply access
   */
  int privScheduleReply = 12;

  /** CalDAV schedule-free-busy access
   */
  int privScheduleFreeBusy = 13;

  /** Unbind (destroy) access
   */
  int privUnbind = 14;

  /** Unlock access
   */
  int privUnlock = 15;

  /* ----------------- CalDAV Scheduling ------------------------ */

  /** CalDAV schedule access
   */
  int privScheduleDeliver = 16;

  /** CalDAV schedule access
   */
  int privScheduleDeliverInvite = 17;

  /** CalDAV schedule access
   */
  int privScheduleDeliverReply = 18;

  /** CalDAV schedule access
   */
  int privScheduleQueryFreebusy = 19;

  /** CalDAV schedule access
   */
  int privScheduleSend = 20;

  /** CalDAV schedule access
   */
  int privScheduleSendInvite = 21;

  /** CalDAV schedule access
   */
  int privScheduleSendReply = 22;

  /** CalDAV schedule access
   */
  int privScheduleSendFreebusy = 23;

  /** Deny all access */
  int privNone = 24;

  /** Max access index
   */
  int privMaxType = 24;

  /** Indicate any allowed access will do
   */
  int privAny = privMaxType + 1;


  /* !!!!!!!!!!!!!!!!!! need default access - i.e. remove any mention of who
   */

  /** Single char encoding
   * BCGHJKLMOVXYZ
   * dfghjklmnovwxz
   */
  char[] privEncoding = {
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
