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

import edu.rpi.cmt.access.Access.AccessCb;
import edu.rpi.sss.util.ObjectPool;

/** describe who we are giving access to. This object once created is immutable.
 *
 * @author douglm - rpi.edu
 */
public final class AceWho implements WhoDefs, Comparable<AceWho> {
  private String who;

  private int whoType;

  private boolean notWho;

  private static ObjectPool<String> whos = new ObjectPool<String>();

  private static ObjectPool<AceWho> aceWhos = new ObjectPool<AceWho>();

  private static boolean poolAceWhos = true;

  /** Represents all */
  public static final AceWho all = getAceWho(null, Ace.whoTypeAll, false);

  /** Represents an owner */
  public static final AceWho owner = getAceWho(null, Ace.whoTypeOwner, false);

  /** Represents other than owner */
  public static final AceWho other = getAceWho(null, Ace.whoTypeOther, false);

  /** Represents unauthenticated users */
  public static final AceWho unauthenticated = getAceWho(null,
                                                         Ace.whoTypeUnauthenticated,
                                                         false);

  /** Gat an AceWho corresponding to the parameters.
   *
   * @param who
   * @param whoType
   * @param notWho
   * @return an AceWho value
   */
  public static AceWho getAceWho(String who,
                                 int whoType,
                                 boolean notWho) {
    if (poolAceWhos) {
      return aceWhos.get(new AceWho(who, whoType, notWho));
    } else {
      return new AceWho(who, whoType, notWho);
    }
  }
  /**
   */
  private AceWho() {
  }

  /**
   * @param who
   * @param whoType
   * @param notWho
   */
  private AceWho(String who,
                 int whoType,
                 boolean notWho) {
    this.who = whos.get(who);
    this.notWho = notWho;
    this.whoType = whoType;
  }

  /** Get who this entry is for
   *
   * @return String who
   */
  public String getWho() {
    return who;
  }

  /**
   * @return boolean who/not who flag
   */
  public boolean getNotWho() {
    return notWho;
  }

  /**
   * @return boolean  type of who
   */
  public int getWhoType() {
    return whoType;
  }

  /**
   * @param cb
   * @param pref  full principal name
   * @return boolean true if the name matches
     * @throws AccessException
   */
  public boolean whoMatch(AccessCb cb, String pref) throws AccessException {
    if ((pref == null) && (getWho() == null)) {
      return !getNotWho();
    }

    if ((pref == null) || (getWho() == null)) {
      return getNotWho();
    }

    boolean match = pref.equals(cb.makeHref(getWho(), whoType));
    if (getNotWho()) {
      match = !match;
    }

    return match;
  }

  /* ====================================================================
   *                 De/Encoding methods
   * ==================================================================== */

  /** Encode this object as a sequence of char. privs must have been set.
   *
   * @param acl   EncodedAcl
   * @throws AccessException
   */
  public void encode(EncodedAcl acl) throws AccessException {
    if (notWho) {
      acl.addChar(notWhoFlag);
    } else {
      acl.addChar(whoFlag);
    }

    acl.addChar(whoTypeFlags[whoType]);

    acl.encodeString(who);
  }

  /** Skip the who part in an encoded Acl
   *
   * @param acl
   * @throws AccessException
   */
  public static void skip(EncodedAcl acl) throws AccessException {
    acl.getChar();
    acl.getChar();
    acl.skipString();
  }

  /** Create AceWho from an encoded Acl
   *
   * @param acl
   * @return new AceWho
   * @throws AccessException
   */
  public static AceWho decode(EncodedAcl acl) throws AccessException {
    char c = acl.getChar();
    boolean notWho;
    int whoType;

    if (c == notWhoFlag) {
      notWho = true;
    } else if (c == whoFlag) {
      notWho = false;
    } else {
      throw AccessException.badACE("who/notWho flag");
    }

    c = acl.getChar();

    getWhoType:{
      for (whoType = 0; whoType < whoTypeFlags.length; whoType++) {
        if (c == whoTypeFlags[whoType]) {
          break getWhoType;
        }
      }

      throw AccessException.badACE("who type");
    }

    return getAceWho(acl.getString(), whoType, notWho);
  }

  /** Provide a string representation for user display - this should probably
   * use a localized resource and be part of a display level. It also requires
   * the Privilege objects
   *
   * @return String representation
   */
  public String toUserString() {
    StringBuffer sb = new StringBuffer();

    sb.append(whoTypeNames[whoType]);
    if (notWho) {
      sb.append("NOT ");
    }

    sb.append(whoTypeNames[whoType]);

    if ((Ace.whoTypeNamed[whoType])) {
      sb.append("=");
      sb.append(getWho());
    }

    return sb.toString();
  }

  /* (non-Javadoc)
   * @see java.lang.Comparable#compareTo(java.lang.Object)
   */
  public int compareTo(AceWho that) {
    if (this == that) {
      return 0;
    }

    if (notWho != that.notWho) {
      if (notWho) {
        return -1;
      }
      return 1;
    }

    if (whoType < that.whoType) {
      return -1;
    }

    if (whoType > that.whoType) {
      return 1;
    }

    if (!Ace.whoTypeNamed[whoType]) {
      return 0;
    }

    return compareWho(who, that.who);
  }

  public int hashCode() {
    int hc = 7;

    if (who != null) {
      hc *= who.hashCode();
    }

    if (notWho) {
      hc *= 2;
    }

    return hc *= whoType;
  }

  public boolean equals(Object o) {
    return compareTo((AceWho)o) == 0;
  }

  public String toString() {
    StringBuffer sb = new StringBuffer();

    sb.append("AceWho{who=");
    sb.append(who);
    sb.append(", notWho=");
    sb.append(notWho);
    sb.append(", whoType=");
    sb.append(whoTypeNames[whoType]);
    sb.append("(");
    sb.append(whoType);
    sb.append(")");

    sb.append("}");

    return sb.toString();
  }

  /* ====================================================================
   *                   Private methods
   * ==================================================================== */

  private int compareWho(String who1, String who2) {
    if ((who1 == null) && (who2 == null)) {
      return 0;
    }

    if (who1 == null) {
      return -1;
    }

    if (who2 == null) {
      return 1;
    }

    return who1.compareTo(who2);
  }
}
