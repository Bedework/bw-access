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

/** Various exceptions that can arise during access checks
 *
 * @author Mike Douglass douglm @ bedework.org
 *
 */
public class AccessException extends RuntimeException {
  private static final String badACEMsg = "org.bedework.cmt.access.badace";

  private static final String badACLMsg = "org.bedework.cmt.access.badacl";

  private static final String badACLLengthMsg = "org.bedework.cmt.access.badacllength";

  private static final String badACLRewindMsg = "org.bedework.cmt.access.badaclrewinf";

  private static final String badXmlACLMsg = "org.bedework.cmt.access.badxmlacl";

  /**
   *
   * @param s String exception message
   */
  public AccessException(final String s) {
    super(s);
  }

  /**
   *
   * @param s String exception message
   * @param extra String exception message parameter
   */
  public AccessException(final String s, final String extra) {
    super(s + " " + extra);
  }

  /**
   *
   * @param t Throwable to wrap
   */
  public AccessException(final Throwable t) {
    super(t);
  }

  /** We got a bad ACE
   *
   * @param extra String explanation
   * @return AccessException
   */
  public static AccessException badACE(final String extra) {
    return new AccessException(badACEMsg, extra);
  }

  /** We got a bad acl
   *
   * @param extra information
   * @return AccessException
   */
  public static AccessException badACL(final String extra) {
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
   * @param extra information
   * @return AccessException
   */
  public static AccessException badXmlACL(final String extra) {
    return new AccessException(badXmlACLMsg, extra);
  }
}

