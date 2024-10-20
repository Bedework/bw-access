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

import org.bedework.util.caching.ObjectPool;

/** describe who we are giving access to. This object once created is immutable.
 *
 * @author douglm - bedework.org
 */
public final class AceWho implements WhoDefs, Comparable<AceWho> {
  private final String who;

  private final int whoType;

  private final boolean notWho;

  private static final ObjectPool<String> whos = new ObjectPool<>();

  private static final ObjectPool<AceWho> aceWhos = new ObjectPool<>();

  private static final boolean poolAceWhos = true;

  /** Represents all */
  public static final AceWho all = getAceWho(null, whoTypeAll, false);

  /** Represents an owner */
  public static final AceWho owner = getAceWho(null, whoTypeOwner, false);

  /** Represents other than owner */
  public static final AceWho other = getAceWho(null, whoTypeOther, false);

  /** Represents unauthenticated users */
  public static final AceWho unauthenticated = getAceWho(null,
                                                         whoTypeUnauthenticated,
                                                         false);

  /** Gat an AceWho corresponding to the parameters.
   *
   * @param who principal
   * @param whoType type of principal
   * @param notWho invert if true
   * @return an AceWho value
   */
  public static AceWho getAceWho(final String who,
                                 final int whoType,
                                 final boolean notWho) {
    if (poolAceWhos) {
      return aceWhos.get(new AceWho(who, whoType, notWho));
    } else {
      return new AceWho(who, whoType, notWho);
    }
  }

  /**
   * @param who principal
   * @param whoType type of principal
   * @param notWho invert if true
   */
  private AceWho(final String who,
                 final int whoType,
                 final boolean notWho) {
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
   * @param cb for makeHref
   * @param pref  full principal name
   * @return boolean true if the name matches
   */
  public boolean whoMatch(final Access.AccessCb cb, final String pref) {
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
   */
  public void encode(final EncodedAcl acl) {
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
   * @param acl in encoded form
   */
  public static void skip(final EncodedAcl acl) {
    acl.getChar();
    acl.getChar();
    acl.skipString();
  }

  /** Create AceWho from an encoded Acl
   *
   * @param acl in encoded form
   * @return new AceWho
   */
  public static AceWho decode(final EncodedAcl acl) {
    char c = acl.getChar();
    final boolean notWho;
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
    final StringBuilder sb = new StringBuilder();

    sb.append(whoTypeNames[whoType]);
    if (notWho) {
      sb.append("NOT ");
    }

    sb.append(whoTypeNames[whoType]);

    if ((whoTypeNamed[whoType])) {
      sb.append("=");
      sb.append(getWho());
    }

    return sb.toString();
  }

  @Override
  public int compareTo(final AceWho that) {
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

    if (!whoTypeNamed[whoType]) {
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

    return hc * whoType;
  }

  public boolean equals(final Object o) {
    return compareTo((AceWho)o) == 0;
  }

  public String toString() {
    final StringBuilder sb = new StringBuilder("AceWho{");

    if (notWho) {
      sb.append("NOT ");
    }
    sb.append(whoTypeNames[whoType])
      .append("(")
      .append(whoType)
      .append(")");
    if (whoTypeNamed[whoType]) {
      sb.append(": ").append(who);
    }

    return sb.append("}").toString();
  }

  /* ========================================================
   *                   Private methods
   * ======================================================== */

  private int compareWho(final String who1, final String who2) {
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
