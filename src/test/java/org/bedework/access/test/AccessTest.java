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
package org.bedework.access.test;

import org.bedework.access.Access.AccessCb;
import org.bedework.access.AccessException;
import org.bedework.access.Ace;
import org.bedework.access.AceWho;
import org.bedework.access.Acl;
import org.bedework.access.CurrentAccess;
import org.bedework.access.EvaluatedAccessCache;
import org.bedework.access.Privilege;
import org.bedework.access.Privileges;

import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.Collection;

/** Test the access classes
 *
 * @author Mike Douglass       douglm@bedework.edu
   @version 1.0
 */
public class AccessTest extends TestCase {
  boolean debug = true;

  static class TestAccessCb implements AccessCb {
    public String makeHref(String id, int whoType) throws AccessException {
      if (id.startsWith("/principals")) {
        return id;
      }

      if (whoType == Ace.whoTypeUser) {
        return "/principals/users/" + id;
      }

      if (whoType == Ace.whoTypeGroup) {
        return "/principals/groups/" + id;
      }

      return id;
    }
  }

  /**
   *
   */
  public void testBasics() {
    try {
      // Make some test objects
      User unauth = new User();
      User owner = new User("anowner");
      User auser = new User("auser");
      User auserInGroup = new User("auseringroup");

      Group agroup = new Group("agroup");
      Group bgroup = new Group("bgroup");

      auserInGroup.addGroup(agroup);
      auserInGroup.addGroup(bgroup);

      Group cgroup = new Group("cgroup");

      cgroup.addGroup(agroup);

      User userInCgroup = new User("userincgroup");
      userInCgroup.addGroup(cgroup);
      userInCgroup.addGroup(agroup); // cgroup is in agroup

      Privilege read = Privileges.makePriv(Privileges.privRead);
      Privilege delete = Privileges.makePriv(Privileges.privUnbind);
      Privilege write = Privileges.makePriv(Privileges.privWrite);
      Privilege writeContent = Privileges.makePriv(Privileges.privWriteContent);

      Privilege[] privSetRead = {read};
      Privilege[] privSetWrite = {write};
      Privilege[] privSetWriteContent = {writeContent};
      Privilege[] privSetReadWrite = {read, write};
      Privilege[] privSetReadWriteContent = {read, writeContent};
      Privilege[] privSetDelete = {delete};

      /* See what we get when we encode a null - acl.
       *
       * I think this is no longer true. There is no default acl


      Acl acl = new Acl(debug);

      char[] encoded = logEncoded(acl, "default");
      tryDecode(encoded, "default");
      tryEvaluateAccess(owner, owner, privSetRead, encoded, true,
                        "Owner access for default");
      tryEvaluateAccess(auser, owner, privSetRead, encoded, false,
                        "User access for default");
                        */

      log("---------------------------------------------------------");

      /* read others - i.e. not owner */

      Collection<Privilege> readPrivs = new ArrayList<Privilege>();
      readPrivs.add(read);

      Collection<Ace> aces = new ArrayList<Ace>();

      aces.add(Ace.makeAce(AceWho.other, readPrivs, null));

      char[] encoded = logEncoded(new Acl(aces), "read others");
      tryDecode(encoded, "read others");
      tryEvaluateAccess(owner, owner, privSetReadWrite, encoded, true,
                        "Owner access for read others");
      tryEvaluateAccess(auser, owner, privSetRead, encoded, true,
                        "User access for read others");
      tryEvaluateAccess(unauth, owner, privSetRead, encoded, true,
                        "Unauthenticated access for read others");

      log("---------------------------------------------------------");

      /* read for group "agroup", rw for user "auser" */
      aces.clear();

      Collection<Privilege> privs = new ArrayList<Privilege>();
      privs.add(read);

      Collection<Privilege> noPrivs = new ArrayList<Privilege>();
      noPrivs.add(Privileges.makePriv(Privileges.privNone));

      AceWho who = AceWho.getAceWho("agroup",
                                    Ace.whoTypeGroup,
                                    false);
      aces.add(Ace.makeAce(who, privs, null));

      who = AceWho.getAceWho("auser", Ace.whoTypeUser, false);
      privs.clear();
      privs.add(Privileges.makePriv(Privileges.privRead));
      privs.add(Privileges.makePriv(Privileges.privWriteContent));
      aces.add(Ace.makeAce(who, privs, null));

      encoded = logEncoded(new Acl(aces), "read g=agroup,rw auser");
      tryDecode(encoded, "read g=agroup,rw auser");
      tryEvaluateAccess(owner, owner, privSetReadWriteContent, encoded, true,
                        "Owner access for read g=agroup,rw auser");
      tryEvaluateAccess(auserInGroup, owner, privSetRead, encoded, true,
                        "User access for read g=agroup,rw auser");
      tryEvaluateAccess(userInCgroup, owner, privSetRead, encoded, true,
                        "userInCgroup access for read g=agroup,rw auser");
      tryEvaluateAccess(auser, owner, privSetRead, encoded, true,
                        "auser access for read g=agroup,rw auser");
      tryEvaluateAccess(auser, owner, privSetWriteContent, encoded, true,
                        "auser access for write g=agroup,rw auser");
      tryEvaluateAccess(auser, owner, privSetWrite, encoded, false,
      "auser access for write g=agroup,rw auser");
      tryEvaluateAccess(auser, owner, privSetDelete, encoded, false,
      "auser access for write g=agroup,rw auser");

      log("---------------------------------------------------------");

      /* read for group "agroup", rw for user "auser" */
      aces.clear();

      aces.add(Ace.makeAce(AceWho.all, readPrivs, null));

      aces.add(Ace.makeAce(AceWho.unauthenticated, noPrivs, null));

      encoded = logEncoded(new Acl(aces), "read others,none unauthenticated");
      tryDecode(encoded, "read others,none unauthenticated");
      tryEvaluateAccess(owner, owner, privSetReadWrite, encoded, true,
                        "Owner access for read others,none unauthenticated");
      tryEvaluateAccess(auser, owner, privSetRead, encoded, true,
                        "User access for read others,none unauthenticated");
      tryEvaluateAccess(unauth, owner, privSetRead, encoded, false,
                        "Unauthenticated access for read others,none unauthenticated");
    } catch (Throwable t) {
      t.printStackTrace();
      fail("Exception testing access: " + t.getMessage());
    }
  }

  /* ====================================================================
   *                       Private methods.
   * ==================================================================== */

  private void tryEvaluateAccess(Principal who, Principal owner,
                                 Privilege[] how, char[] encoded,
                                 boolean expected, String title) throws Throwable {
    CurrentAccess ca =
            EvaluatedAccessCache.evaluateAccess(new TestAccessCb(),
                                                who, owner, how,
                                                encoded, null);

    if (debug) {
      log(title + " got " + ca.getAccessAllowed() + " and expected " + expected);
    }
    assertEquals(title, expected, ca.getAccessAllowed());
  }

  private void tryDecode(char[] encoded, String title) throws Throwable {
    Acl acl = Acl.decode(encoded);
    log("Result of decoding " + title);
    log(acl.toString());
    log(acl.toUserString());
  }

  private char[] logEncoded(Acl acl, String title) throws Throwable {
    char [] encoded = acl.encode();

    if (encoded == null) {
      log(title + "=NULL");
      return null;
    }

    String s = new String(encoded);

    log(title + "='" + s + "'");

    return encoded;
  }

  private void log(String msg) {
    System.out.println(this.getClass().getName() + ": " + msg);
  }
}

