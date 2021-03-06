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
import java.util.Collection;

/** Class used when determining access.
 *
 * @author Mike Douglass
 *
 */
public interface AccessPrincipal extends Serializable {
  /** Return the kind of Principal, e.g. user/group etc.
   * Values come from Ace.whoTypeXXX
   *
   * @return int kind
   */
  int getKind();

  /** Set the unauthenticated state.
   *
   * @param val unauthenticated state
   */
  void setUnauthenticated(boolean val);

  /**
   * @return  boolean unauthenticated state
   */
  boolean getUnauthenticated();

  /** This is the external account name - that which we generally show the user.
   * It may be sufficient to uniquely identify the principal, at least in context.
   *
   * <p>That is, at certain points we can assume the string "jim" refers to the
   * user principal "/principals/users/jim" if that is how we store them.
   *
   * <p>The field principalRef is set to a value which uniquely identifies the
   * principal, using prefixes or paths for example.
   *
   * <p>The access routines do
   * @param val account
   */
  void setAccount(String val);

  /**
   * @return  String account name
   */
  String getAccount();

  /** This is a fix to get around an issue with shortened names in the
   * acl. If we have a principal href of /principals/groups/bwadmin/groupa
   * we lost the bwadmin segment of the name. This should return
   * bwadmin/groupa while getAccount() will return groupa
   *
   * @return  String account name to store in acl
   */
  String getAclAccount();

  /** This is the value which uniquely identifies the
   * principal, using prefixes or paths for example.
   *
   * <p>The access routines do not use this field for access evaluation.
   *
   * @param val principal reference
   */
  void setPrincipalRef(String val);

  /**
   * @return  String principal reference
   */
  String getPrincipalRef();

  /** Set of groupNames of which principal is a member. These are not just those
   * of which the principal is a direct member but also those it is a member of
   * by virtue of membership of other groups. For example <br/>
   * If the principal is a member of groupA and groupA is a member of groupB
   * the groupB should appear in the list.
   *
   * @param val        Set of String
   */
  @SuppressWarnings("UnusedDeclaration")
  void setGroupNames(Collection<String> val);

  /** Get the group principal names of which principal is a member.
   *
   * @return Set    of String
   */
  Collection<String> getGroupNames();

  /** Set the description of the principal.
   *
   * @param   val     String principal description.
   */
  void setDescription(String val);

  /** Return the description of the principal.
   *
   * @return String        principal description
   */
  String getDescription();
}
