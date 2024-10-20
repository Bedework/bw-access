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

/** describe who we are giving access to
 * @author douglm - bedework.org
 */
public interface WhoDefs extends Serializable {
  /** Who defines a principal, NotWho means the principal must not be
     defined by the 'who', e.g. NOT IN group bgroup
   */
  char whoFlag = 'W';
  /** */
  char notWhoFlag = 'N';

  /** */
  char whoFlagOwner = 'O';
  /** */
  char whoFlagUser = 'U';
  /** */
  char whoFlagGroup = 'G';
  /** */
  char whoFlagTicket = 'T';
  /** */
  char whoFlagResource = 'R';
  /** */
  char whoFlagVenue = 'V';
  /** */
  char whoFlagHost = 'H';
  /** */
  char whoFlagUnauthenticated = 'X';
  /** */
  char whoFlagAuthenticated = 'A';
  /** */
  char whoFlagOther = 'Z';
  /** */
  char whoFlagAll = 'L';

  /* Define for whom we are checking access */

  /** The entity owner */
  int whoTypeOwner = 0;

  /** A named user */
  int whoTypeUser = 1;

  /** A named group */
  int whoTypeGroup = 2;

  /** A named host */
  int whoTypeHost = 3;  // Named host

  /** A ticket */
  int whoTypeTicket = 4;

  /** A resource */
  int whoTypeResource = 5;

  /** A venue */
  int whoTypeVenue = 6; // or location e.g. room

  /** An unauthenticated user */
  int whoTypeUnauthenticated = 7;  // Unauthenticated user

  /** An authenticated user */
  int whoTypeAuthenticated = 8;  // Authenticated user

  /** Somebody other than the owner */
  int whoTypeOther = 9;

  /** Anywho */
  int whoTypeAll = 10; // Unauth + auth

  /** indexed by whoType */
  char[] whoTypeFlags = {
    whoFlagOwner,
    whoFlagUser,
    whoFlagGroup,
    whoFlagHost,
    whoFlagTicket,
    whoFlagResource,
    whoFlagVenue,
    whoFlagUnauthenticated,
    whoFlagAuthenticated,
    whoFlagOther,
    whoFlagAll
  };

  /** indexed by whoType - flag who types that require a name*/
  boolean[] whoTypeNamed = {
    false,              // whoTypeOwner,
    true,               // whoTypeUser,
    true,               // whoTypeGroup,
    true,               // whoTypeHost,
    true,               // whoFlagTicket,
    true,               // whoFlagResource,
    true,               // whoFlagVenue,
    false,              // whoTypeUnauthenticated,
    false,              // whoTypeAuthenticated
    false,              // whoFlagOther
    false,              // whoFlagAll
  };

  /** String name of each who type. These are keys to the resources for locale
   * specific displays
   *
   */
  String[] whoTypeNames = {
    "owner",              // whoTypeOwner,
    "user",               // whoTypeUser,
    "group",              // whoTypeGroup,
    "host",               // whoTypeHost,
    "ticket",             // whoFlagTicket,
    "resource",           // whoFlagResource,
    "venue",              // whoFlagVenue,
    "unauthenticated",    // whoTypeUnauthenticated,
    "authenticated",      // whoTypeAuthenticated
    "other",              // whoFlagOther
    "all",                // whoFlagAll
  };
}
