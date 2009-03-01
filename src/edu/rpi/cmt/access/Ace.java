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

import edu.rpi.sss.util.ObjectPool;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/** Immutable object to represent an ace for a calendar entity or service.
 *
 * <p>The compareTo method orders the Aces according to the notWho, whoType and
 * who components. It does not take the actual privileges into account. There
 * should only be one entry per the above combination and the latest one on the
 * path should stand.
 *
 *  @author Mike Douglass   douglm   rpi.edu
 */
public class Ace implements PrivilegeDefs, WhoDefs, Comparable<Ace> {
  boolean debug;

  private AceWho who;

  /** allowed/denied/undefined indexed by Privilege index
   */
  private PrivilegeSet how;

  /** Privilege objects defining the access. Used when manipulating acls
   */
  Collection<Privilege> privs;

  private String inheritedFrom;

  private static ObjectPool<String> inheritedFroms = new ObjectPool<String>();

  /**
   * @param who
   * @param privs
   * @param inheritedFrom
   */
  public Ace(final AceWho who,
             final Collection<Privilege> privs,
             final String inheritedFrom) {
    this.who = who;

    how = new PrivilegeSet();
    this.privs = new ArrayList<Privilege>();
    if (privs != null) {
      for (Privilege p: privs) {
        this.privs.add(p);
        how = PrivilegeSet.addPrivilege(how, p);
      }
    }

    if (inheritedFrom == null) {
      this.inheritedFrom = null;
    } else {
      this.inheritedFrom = inheritedFroms.get(inheritedFrom);
    }

  }

  /** Get who this entry is for
   *
   * @return AceWho who
   */
  public AceWho getWho() {
    return who;
  }

  /**
   *
   * @return PrivilegeSet array of allowed/denied/undefined indexed by Privilege index
   */
  public PrivilegeSet getHow() {
    if (how == null) {
      how = new PrivilegeSet();
    }

    return how;
  }

  /**
   *
   * @return Collection of Privilege objects defining the access. Used when manipulating acls
   */
  public Collection<Privilege> getPrivs() {
    if (privs == null) {
      return Collections.emptyList();
    }

    return Collections.unmodifiableCollection(privs);
  }

  /**
   * @return String
   */
  public String getInheritedFrom() {
    return inheritedFrom;
  }

  /** Return the merged privileges for all aces which match the name and whoType.
   *
   * @param acl
   * @param name
   * @param whoType
   * @return PrivilegeSet    merged privileges if we find a match else null
   * @throws AccessException
   */
  public static PrivilegeSet findMergedPrivilege(Acl acl,
                                                 String name,
                                                 int whoType) throws AccessException {
    PrivilegeSet privileges = null;
    for (Ace ace: acl.getAces()) {
      if ((whoType == ace.who.getWhoType()) &&
          ((whoType == AceWho.whoTypeUnauthenticated) ||
           (whoType == AceWho.whoTypeAuthenticated) ||
           (whoType == AceWho.whoTypeAll) ||
           (whoType == AceWho.whoTypeOwner) ||
            ace.getWho().whoMatch(name))) {
        privileges = PrivilegeSet.mergePrivileges(privileges, ace.getHow(),
                                                  ace.getInheritedFrom() != null);
      }
    }

    return privileges;
  }

  /* ====================================================================
   *                 Decoding methods
   * ==================================================================== */

  /** Get the next ace in the acl.
   *
   * @param acl
   * @param path If non-null flags an inherited ace
   * @return Ace
   * @throws AccessException
   */
  public static Ace decode(EncodedAcl acl,
                           String path) throws AccessException {
    AceWho who = AceWho.decode(acl);

    //int pos = acl.getPos();

    //PrivilegeSet how = PrivilegeSet.fromEncoding(acl);

    //acl.setPos(pos);

    Collection<Privilege> privs = Privileges.getPrivs(acl);

    // See if we got an inherited flag
    acl.back();

    String  inheritedFrom = null;

    if (acl.getChar() == PrivilegeDefs.inheritedFlag) {
      inheritedFrom = acl.getString();
      if (acl.getChar() != ' ') {
        throw new AccessException("malformedAcl");
      }
    }

    if (inheritedFrom == null) {
      inheritedFrom = path;  // May come from here
    }

    return new Ace(who, privs, inheritedFrom);
  }

  /* ====================================================================
   *                 Encoding methods
   * ==================================================================== */

  /** Encode this object as a sequence of char. privs must have been set.
   *
   * @param acl   EncodedAcl
   * @throws AccessException
   */
  public void encode(EncodedAcl acl) throws AccessException {
    getWho().encode(acl);

    for (Privilege p: privs) {
      p.encode(acl);
    }

    if (inheritedFrom != null) {
      acl.addChar(PrivilegeDefs.inheritedFlag);
      acl.encodeString(inheritedFrom);
    }

    acl.addChar(' ');  // terminate privs.
  }

  /** Provide a string representation for user display - this should probably
   * use a localized resource and be part of a display level. It also requires
   * the Privilege objects
   *
   * @return String representation
   */
  public String toUserString() {
    StringBuilder sb = new StringBuilder("(");

    sb.append(getWho().toUserString());
    sb.append(" ");

    for (Privilege p: privs) {
      sb.append(p.toUserString());
      sb.append(" ");
    }
    sb.append(")");

    return sb.toString();
  }

  /* ====================================================================
   *                   Object methods
   * ==================================================================== */

  public int compareTo(Ace that) {
    if (this == that) {
      return 0;
    }

    int res = getWho().compareTo(that.getWho());
    if (res == 0) {
      res = getHow().compareTo(that.getHow());
    }

    return res;
  }

  public int hashCode() {
    int hc = 7;

    if (who != null) {
      hc *= who.hashCode();
    }

    return hc *= getHow().hashCode();
  }

  public boolean equals(Object o) {
    return compareTo((Ace)o) == 0;
  }

  public String toString() {
    StringBuilder sb = new StringBuilder();

    sb.append("Ace{");
    sb.append(getWho().toString());
    if (how != null) {
      sb.append(", how=");
      sb.append(how);
    }

    if (getInheritedFrom() != null) {
      sb.append(", inherited from \"");
      sb.append(getInheritedFrom());
      sb.append("\"");
    }

    sb.append(", \nprivs=[");

    for (Privilege p: privs) {
      sb.append(p.toString());
      sb.append("\n");
    }
    sb.append("]");

    sb.append("}");

    return sb.toString();
  }
}

