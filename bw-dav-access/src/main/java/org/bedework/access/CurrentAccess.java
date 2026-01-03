/* ********************************************************************
    Appropriate copyright notice
*/
package org.bedework.access;

import org.bedework.base.ToString;
import org.bedework.util.misc.Util;

import java.io.Serializable;
import java.util.Arrays;

/** Immutable object created as a result of evaluating access to an entity for
 * a principal
 * <br/>
 * User: mike Date: 12/11/18 Time: 23:14
 */
public class CurrentAccess implements Serializable,
        Comparable<CurrentAccess> {
  /** The Acl used to evaluate the access. We should not necessarily
   * make this available to the client.
   */
  Acl acl;

  char[] aclChars;

  PrivilegeSet privileges = null;

  /** Was it successful */
  boolean accessAllowed;

  /**
   *
   */
  public CurrentAccess() {
  }

  /**
   * @param privs the privilege set
   */
  public CurrentAccess(final PrivilegeSet privs) {
    privileges = privs;
  }

  /**
   * @param accessAllowed true if access is allowed
   */
  public CurrentAccess(final boolean accessAllowed) {
    this.accessAllowed = accessAllowed;
  }

  CurrentAccess(final Acl acl, final char[] aclChars) {
    this.acl = acl;
    this.aclChars = aclChars;
  }

  /** The Acl used to evaluate the access. We should not necessarily
   * make this available to the client.
   *
   * @return acl
   */
  public Acl getAcl() {
    return acl;
  }

  /**  Allowed access for each privilege type
   * @see PrivilegeDefs
   *
   * @return privileges
   */
  public PrivilegeSet getPrivileges() {
    return privileges;
  }

  /** Is access allowed to this?
   *
   * @return boolean
   */
  public boolean getAccessAllowed() {
    return accessAllowed;
  }

  @Override
  public int compareTo(final CurrentAccess that) {
    if (this == that) {
      return 0;
    }

    int res = Util.compare(aclChars, that.aclChars);

    if (res != 0) {
      return res;
    }

    res = Util.cmpObjval(privileges, that.privileges);

    if (res != 0) {
      return res;
    }

    return Util.cmpBoolval(accessAllowed, that.accessAllowed);
  }

  @Override
  public int hashCode() {
    int hc = 7;

    if (aclChars != null) {
      hc *= Arrays.hashCode(aclChars);
    }

    if (privileges != null) {
      hc *= privileges.hashCode();
    }

    return hc;
  }

  @Override
  public boolean equals(final Object o) {
    return (o instanceof CurrentAccess) &&
            compareTo((CurrentAccess)o) == 0;
  }

  @Override
  public String toString() {
    return new ToString(this)
            .append("acl", acl)
            .append("accessAllowed", accessAllowed)
            .toString();
  }
}
