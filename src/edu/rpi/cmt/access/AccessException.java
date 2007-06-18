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

/** Various exceptions that can arise during access checks
 *
 * @author Mike Douglass douglm @ rpi.edu
 *
 */
public class AccessException extends Exception {
  private static final String badACEMsg = "edu.rpi.cmt.access.badace";

  private static final String badACLMsg = "edu.rpi.cmt.access.badacl";

  private static final String badACLLengthMsg = "edu.rpi.cmt.access.badacllength";

  private static final String badACLRewindMsg = "edu.rpi.cmt.access.badaclrewinf";

  private static final String badXmlACLMsg = "edu.rpi.cmt.access.badxmlacl";

  /**
   *
   * @param s String exception message
   */
  public AccessException(String s) {
    super(s);
  }

  /**
   *
   * @param s String exception message
   * @param extra String exception message parameter
   */
  public AccessException(String s, String extra) {
    super(s + " " + extra);
  }

  /**
   *
   * @param t Throwable to wrap
   */
  public AccessException(Throwable t) {
    super(t);
  }

  /** We got a bad ACE
   *
   * @param extra String explanation
   * @return AccessException
   */
  public static AccessException badACE(String extra) {
    return new AccessException(badACEMsg, extra);
  }

  /** We got a bad acl
   *
   * @param extra
   * @return AccessException
   */
  public static AccessException badACL(String extra) {
    return new AccessException(badACLMsg, extra);
  }

  /** Error rewinging an ACL
   *
   * @return AccessException
   */
  public static AccessException badACLRewind() {
    return new AccessException(badACLRewindMsg);
  }

  /** ACL length is wrong
   *
   * @return AccessException
   */
  public static AccessException badACLLength() {
    return new AccessException(badACLLengthMsg);
  }

  /** We got a bad xml acl
   *
   * @param extra
   * @return AccessException
   */
  public static AccessException badXmlACL(String extra) {
    return new AccessException(badXmlACLMsg, extra);
  }
}

