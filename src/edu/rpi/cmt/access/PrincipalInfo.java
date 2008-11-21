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

import edu.rpi.sss.util.Util;

/** This class is the result of interpreting a principal url
 *
 * @author douglm
 *
 */
public class PrincipalInfo {
  /** From WhoDefs */
  public int whoType;   // from access.Ace user, group etc
  /** */
  public String who;    // id of user group etc.
  /** */
  public String prefix; // prefix of hierarchy e.g. /principals/users

  /** Set false if principal is not valid. */
  public boolean valid;

  /**
   *
   */
  public PrincipalInfo() {
  }

  /**
   * @param whoType
   * @param who
   * @param prefix
   */
  public PrincipalInfo(int whoType, String who, String prefix) {
    this.whoType = whoType;
    this.who = who;
    this.prefix = prefix;

    valid = true;
  }

  public int hashCode() {
    int hc = whoType;

    if (who != null) {
      hc *= who.hashCode();
    }

    if (prefix != null) {
      hc *= prefix.hashCode();
    }

    return hc;
  }

  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }

    if (!(o instanceof PrincipalInfo)) {
      return false;
    }

    PrincipalInfo that = (PrincipalInfo)o;

    if (whoType != that.whoType) {
      return false;
    }

    if (Util.cmpObjval(who, that.who) != 0) {
      return false;
    }

    return Util.cmpObjval(prefix, that.prefix) == 0;
  }
}
