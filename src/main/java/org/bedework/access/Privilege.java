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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/** Define the properties of a privilege for the calendar.
 *
 *  @author Mike Douglass   douglm @ bedework.edu
 */
/**
 * @author douglm
 *
 */
public class Privilege implements PrivilegeDefs {
  private String name;

  /** This will probably go - the description needs to come from a resource
   * and be in the appropriate language.
   */
  private String description;

  private boolean abstractPriv;

  /** Is this a denial rather than granting
   */
  private boolean denial;

  private int index;

  private char encoding;

  private ArrayList<Privilege> containedPrivileges = new ArrayList<Privilege>();

  /** Constructor
   *
   * @param name         the privilege name
   * @param description  a description
   * @param abstractPriv is it abstract
   * @param denial       is it a denial
   * @param index        an index
   */
  public Privilege(String name,
                   String description,
                   boolean abstractPriv,
                   boolean denial,
                   int index) {
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
  public Privilege(String name,
                   String description,
                   int index) {
    this(name, description, false, false, index);
  }

  /** Constructor for non-abstract
   *
   * @param name         the privilege name
   * @param description  a description
   * @param denial       is it a denial
   * @param index        an index
   */
  public Privilege(String name,
                   String description,
                   boolean denial,
                   int index) {
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
  public Privilege(String name,
                   String description,
                   boolean denial,
                   int index,
                   Privilege[] contained) {
    this(name, description, false, denial, index);
    for (Privilege p: contained) {
      containedPrivileges.add(p);
    }
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
  public static Privilege findPriv(Privilege allowedRoot,
                                   Privilege deniedRoot,
                                   EncodedAcl acl)
          throws AccessException {
    if (acl.remaining() < 2) {
      return null;
    }

    Privilege p;

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

  private static boolean matchDenied(EncodedAcl acl) throws AccessException {
    char c = acl.getChar();

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
   * @throws AccessException
   */
  private static Privilege matchEncoding(Privilege subRoot,
                                         EncodedAcl acl) throws AccessException {
    if (acl.remaining() < 1) {
      return null;
    }

    char c = acl.getChar();

    //System.out.println("subRoot.encoding='" + subRoot.encoding + " c='" + c + "'");
    if (subRoot.encoding == c) {
      return subRoot;
    }

    /* Try the children */

    acl.back();

    for (Privilege cp: subRoot.getContainedPrivileges()) {
      Privilege p = matchEncoding(cp, acl);
      if (p != null) {
        return p;
      }
    }

    return null;
  }

  /* ====================================================================
   *                 Encoding methods
   * ==================================================================== */

  /** Encode this object as a sequence of char.
   *
   * @param acl   EncodedAcl for result.
   */
  /**
   * @param acl         the encoded ACL
   * @throws AccessException
   */
  public void encode(EncodedAcl acl) throws AccessException {
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
  public static Privilege cloneDenied(Privilege val) {
    Privilege newval = new Privilege(val.getName(),
                                     val.getDescription(),
                                     val.getAbstractPriv(),
                                     true,
                                     val.getIndex());

    for (Privilege p: val.getContainedPrivileges()) {
      newval.containedPrivileges.add(cloneDenied(p));
    }

    return newval;
  }

  /* ====================================================================
   *                    private methods
   * ==================================================================== */

  /**
   * @param val the index
   */
  private void setIndex(int val) {
    index = val;
    encoding = privEncoding[index];
  }

  /* ====================================================================
   *                    Object methods
   * ==================================================================== */
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
   */
  /**
   * @return String
   */
  public String toUserString() {
    StringBuilder sb = new StringBuilder();

    if (getDenial()) {
      sb.append("NOT ");
    }

    sb.append(getName());

    return sb.toString();
  }

  public String toString() {
    StringBuilder sb = new StringBuilder();

    sb.append("Privilege{name=");
    sb.append(name);
    sb.append(", description=");
    sb.append(description);
    sb.append(", abstractPriv=");
    sb.append(abstractPriv);
    sb.append(", denial=");
    sb.append(denial);
    sb.append(", index=");
    sb.append(index);

    if (!containedPrivileges.isEmpty()) {
      sb.append(",\n   contains ");
      boolean first = true;
      for (Privilege p: containedPrivileges) {
        if (!first) {
          sb.append(", ");
        }
        first = false;
        sb.append(p.getName());
      }
    }
    sb.append("}");

    return sb.toString();
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

