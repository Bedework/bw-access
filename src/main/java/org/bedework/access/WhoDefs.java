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
     defined by the 'who',e.g NOT IN group bgroup
   */
  public static final char whoFlag = 'W';
  /** */
  public static final char notWhoFlag = 'N';

  /** */
  public static final char whoFlagOwner = 'O';
  /** */
  public static final char whoFlagUser = 'U';
  /** */
  public static final char whoFlagGroup = 'G';
  /** */
  public static final char whoFlagTicket = 'T';
  /** */
  public static final char whoFlagResource = 'R';
  /** */
  public static final char whoFlagVenue = 'V';
  /** */
  public static final char whoFlagHost = 'H';
  /** */
  public static final char whoFlagUnauthenticated = 'X';
  /** */
  public static final char whoFlagAuthenticated = 'A';
  /** */
  public static final char whoFlagOther = 'Z';
  /** */
  public static final char whoFlagAll = 'L';

  /** Define for whom we are checking access */

  /** The entity owner */
  public static final int whoTypeOwner = 0;

  /** A named user */
  public static final int whoTypeUser = 1;

  /** A named group */
  public static final int whoTypeGroup = 2;

  /** A named host */
  public static final int whoTypeHost = 3;  // Named host

  /** A ticket */
  public static final int whoTypeTicket = 4;

  /** A resource */
  public static final int whoTypeResource = 5;

  /** A venue */
  public static final int whoTypeVenue = 6; // or location e.g. room

  /** An unauthenticated user */
  public static final int whoTypeUnauthenticated = 7;  // Unauthenticated user

  /** An authenticated user */
  public static final int whoTypeAuthenticated = 8;  // Authenticated user

  /** Somebody other than the owner */
  public static final int whoTypeOther = 9;

  /** Anywho */
  public static final int whoTypeAll = 10; // Unauth + auth

  /** indexed by whoType */
  public static final char[] whoTypeFlags = {
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
  public static final boolean[] whoTypeNamed = {
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
  public static final String[] whoTypeNames = {
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
