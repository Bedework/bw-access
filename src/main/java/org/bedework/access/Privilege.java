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

import org.bedework.util.misc.ToString;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/** Define the properties of a privilege for the calendar.
 *
 *  @author Mike Douglass   douglm @ bedework.org
 */
public class Privilege implements PrivilegeDefs,
        ToString.ToStringProducer {
  private final String name;

  /** This will probably go - the description needs to come from a resource
   * and be in the appropriate language.
   */
  private final String description;

  private final boolean abstractPriv;

  /** Is this a denial rather than granting
   */
  private final boolean denial;

  private int index;

  private char encoding;

  private final ArrayList<Privilege> containedPrivileges =
          new ArrayList<>();

  /** Constructor
   *
   * @param name         the privilege name
   * @param description  a description
   * @param abstractPriv is it abstract
   * @param denial       is it a denial
   * @param index        an index
   */
  public Privilege(final String name,
                   final String description,
                   final boolean abstractPriv,
                   final boolean denial,
                   final int index) {
    this.name = name;
    this.description = description;
    this.abstractPriv = abstractPriv;
    this.denial = denial;
    setIndex(index);
  }

  /** Constructor for non-abstract non-denial
   *
   * @param name         the privilege name
   * @param description  a description
   * @param index        an index
   */
  public Privilege(final String name,
                   final String description,
                   final int index) {
    this(name, description, false, false, index);
  }

  /** Constructor for non-abstract
   *
   * @param name         the privilege name
   * @param description  a description
   * @param denial       is it a denial
   * @param index        an index
   */
  public Privilege(final String name,
                   final String description,
                   final boolean denial,
                   final int index) {
    this(name, description, false, denial, index);
  }

  /** Constructor for non-abstract privilege container
   *
   * @param name         the privilege name
   * @param description  a description
   * @param denial       is it a denial
   * @param index        an index
   * @param contained    contained privileges
   */
  public Privilege(final String name,
                   final String description,
                   final boolean denial,
                   final int index,
                   final Privilege[] contained) {
    this(name, description, false, denial, index);
    Collections.addAll(containedPrivileges, contained);
  }

  /**
   * @return String
   */
  public String getName() {
    return name;
  }

  /**
   * @return String
   */
  public String getDescription() {
    return description;
  }

  /**
   * @return String
   */
  public boolean getAbstractPriv() {
    return abstractPriv;
  }

  /**
   * @return String
   */
  public boolean getDenial() {
    return denial;
  }

  /**
   * @return String
   */
  public int getIndex() {
    return index;
  }

  /**
   * @return containedPrivileges
   */
  public Collection<Privilege> getContainedPrivileges() {
    return Collections.unmodifiableCollection(containedPrivileges);
  }

  /* ====================================================================
   *                 Decoding methods
   * ==================================================================== */

  /** Works its way down the tree of privileges finding the highest entry
   * that matches the privilege in the acl.
   *
   * @param allowedRoot allowed privs
   * @param deniedRoot  denied privs
   * @param acl         the encoded ACL
   * @return Privilege
   * @throws AccessException on error
   */
  public static Privilege findPriv(final Privilege allowedRoot,
                                   final Privilege deniedRoot,
                                   final EncodedAcl acl) {
    if (acl.remaining() < 2) {
      return null;
    }

    final Privilege p;

    if (matchDenied(acl)) {
      p = matchEncoding(deniedRoot, acl);
    } else {
      p = matchEncoding(allowedRoot, acl);
    }

    if (p == null) {
      acl.back();  // back up over denied flag
    }

    return p;
  }

  private static boolean matchDenied(final EncodedAcl acl) {
    final char c = acl.getChar();

    /* Expect the privilege allowed/denied flag
     * (or the oldDenied or oldAllowed flag)
     */
    if ((c == denied) || (c == oldDenied)) {
      return true;
    }

    if ((c == allowed) || (c == oldAllowed)) {
      return false;
    }

    throw AccessException.badACE("privilege flag=" + c +
                                         " " + acl.getErrorInfo());
  }

  /** We matched denied at the start. Here only the encoding is compared.
   *
   * @param subRoot Privilege
   * @param acl         the encoded ACL
   * @return Privilege or null
   */
  private static Privilege matchEncoding(final Privilege subRoot,
                                         final EncodedAcl acl) {
    if (acl.remaining() < 1) {
      return null;
    }

    final char c = acl.getChar();

    //System.out.println("subRoot.encoding='" + subRoot.encoding + " c='" + c + "'");
    if (subRoot.encoding == c) {
      return subRoot;
    }

    /* Try the children */

    acl.back();

    for (final Privilege cp: subRoot.getContainedPrivileges()) {
      final Privilege p = matchEncoding(cp, acl);
      if (p != null) {
        return p;
      }
    }

    return null;
  }

  /* ==============================================================
   *                 Encoding methods
   * ============================================================== */

  /** Encode this object as a sequence of char.
   *
   * @param acl   EncodedAcl for result.
   */
  public void encode(final EncodedAcl acl) {
    if (denial) {
      acl.addChar(denied);
    } else {
      acl.addChar(allowed);
    }

    acl.addChar(encoding);
  }

  /** Make a copy including children with the denied flag set true
   *
   * @param val Privilege to clone
   * @return Privilege cloned value
   */
  public static Privilege cloneDenied(final Privilege val) {
    final Privilege newval = new Privilege(val.getName(),
                                           val.getDescription(),
                                           val.getAbstractPriv(),
                                           true,
                                           val.getIndex());

    for (final Privilege p: val.getContainedPrivileges()) {
      newval.containedPrivileges.add(cloneDenied(p));
    }

    return newval;
  }

  /* ==============================================================
   *                    private methods
   * ============================================================== */

  /**
   * @param val the index
   */
  private void setIndex(final int val) {
    index = val;
    encoding = privEncoding[index];
  }

  /* ==============================================================
   *                    Object methods
   * ============================================================== */
/*
  public int hashCode() {
    return 31 * entityId * entityType;
  }

  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (obj == null) {
      return false;
    }

    if (!(obj instanceof AttendeeVO)) {
      return false;
    }

    AttendeePK that = (AttendeePK)obj;

    return (entityId == that.entityId) &&
           (entityType == that.entityType);
  }
  */

  /** Provide a string representation for user display - this should probably
   * use a localized resource
   *
   * @return String
   */
  public String toUserString() {
    final StringBuilder sb = new StringBuilder();

    if (getDenial()) {
      sb.append("NOT ");
    }

    sb.append(getName());

    return sb.toString();
  }

  @Override
  public String toString() {
    final ToString ts = new ToString(this);

    toStringSegment(ts);

    return ts.toString();
  }

  public void toStringWith(final ToString ts) {
    ts.initClass(this);

    toStringSegment(ts);

    ts.closeClass();
  }

  public void toStringSegment(final ToString ts) {
    ts.append(name)
      .appendQ(description);

    if (abstractPriv) {
      ts.append("abstract");
    }

    if (denial) {
      ts.append("denied");
    } else {
      ts.append("allowed");
    }

    ts.append("index").appendParen(String.valueOf(index));

    if (!containedPrivileges.isEmpty()) {
      ts.newLine()
        .append("contains[").clearDelim()
        .indentIn();

      for (final Privilege p: containedPrivileges) {
        ts.append(p.getName());
      }
      ts.indentOut().clearDelim().append("]");
    }
  }

  /** We do not clone the contained privileges - if any.
   *
   * @return Object cloned value
   */
  public Object clone() {
    return new Privilege(getName(),
                         getDescription(),
                         getAbstractPriv(),
                         getDenial(),
                         getIndex());
  }
}

