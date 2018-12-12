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
import org.bedework.util.misc.ToString;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.TreeMap;

/** Immutable object to represent an acl for a calendar entity or service.
 *
 * <p>The objects represented by Privileges will assume transient states
 * during processing.
 *
 * <p>An ACL is a set of ACEs which are stored as an encoded character
 * array. These aces should be sorted to facilitate merging and to
 * allow us to possibly only process as much of the acl as is necessary.
 *
 * <p>For example, owner access should come first, it's first in the test and
 * we can avoid decoding an ace which doesn't include any owner access.
 *
 * <p>The whoTypexxx declarations in Ace define the order of Ace types. In
 * addition, any aces that contain names should be in ascending alphabetic
 * order.
 *
 * <p>In the list of Ace there can only be one entry per AceWho so we can
 * represent the list as a SortedMap. Replacement then becomes easy.
 *
 *  @author Mike Douglass   douglm - bedework.org
 */
public class Acl extends EncodedAcl implements PrivilegeDefs {
  private TreeMap<AceWho, Ace> aces;

  static ObjectPool<PrivilegeSet> privSets = new ObjectPool<PrivilegeSet>();

  static boolean usePool = false;

  static Access.AccessStatsEntry evaluations =
    new Access.AccessStatsEntry("evaluations");

  /** Create a new Acl
   *
   * @param aces
   */
  public Acl(final Collection<Ace> aces) {
    this.aces = new TreeMap<AceWho, Ace>();

    for (Ace ace: aces) {
      this.aces.put(ace.getWho(), ace);
    }
  }

  /** Get the access statistics
   *
   * @return Collection of stats
   */
  public static Collection<Access.AccessStatsEntry> getStatistics() {
    Collection<Access.AccessStatsEntry> stats = new ArrayList<Access.AccessStatsEntry>();

    stats.add(evaluations);
    stats.addAll(Ace.getStatistics());
    stats.addAll(EvaluatedAccessCache.getStatistics());

    return stats;
  }

  /** We use this for things like user home access.
   *
   */
  public static CurrentAccess defaultNonOwnerAccess =
    new CurrentAccess(PrivilegeSet.makeDefaultNonOwnerPrivileges());

  /** We use this for superuser access.
   *
   * @param ca
   * @return new CurrentAccess with access allowed
   */
  public static CurrentAccess forceAccessAllowed(final CurrentAccess ca) {
    CurrentAccess newCa = new CurrentAccess(true);

    newCa.acl = ca.acl;
    newCa.aclChars = ca.aclChars;
    newCa.privileges = ca.privileges;

    return newCa;
  }

  /** Return the ace collection for previously decoded access
   *
   * @return Collection ace collection for previously decoded access
   * @throws AccessException
   */
  public Collection<Ace> getAces() throws AccessException {
    if (aces == null) {
      return null;
    }

    return Collections.unmodifiableCollection(aces.values());
  }

  /** Remove access for a given 'who' entry
   *
   * @param who
   * @return null if unchanged otehrwise new Acl
   * @throws AccessException
   */
  public Acl removeWho(final AceWho who) throws AccessException {
    if (aces == null) {
      return null;
    }

    /* Prescan looking for who */
    boolean contains = false;

    for (Ace a: getAces()) {
      if (who.equals(a.getWho())) {
        contains = true;
        break;
      }
    }

    if (!contains) {
    	return null;
    }

    Collection<Ace> aces = new ArrayList<Ace>();

    for (Ace a: getAces()) {
      if (!who.equals(a.getWho())) {
        aces.add(a);
      }
    }

    return new Acl(aces);
  }

  /* ====================================================================
   *                 Decoding methods
   * ==================================================================== */


  /** Given an encoded acl convert to an ordered sequence of fully expanded
   * ace objects.
   *
   * @param val String val to decode
   * @return decoded Acl
   * @throws AccessException
   */
  public static Acl decode(final String val) throws AccessException {
    return decode(val.toCharArray());
  }

  /** Given an encoded acl convert to an ordered sequence of fully expanded
   * ace objects.
   *
   * @param val char[] val to decode
   * @return decoded Acl
   * @throws AccessException
   */
  public static Acl decode(final char[] val) throws AccessException {
    return decode(val, null);
  }


  /** Given an encoded acl convert to an ordered sequence of fully expanded
   * ace objects.
   *
   * @param val char[] val to decode
   * @param path
   * @return decoded Acl
   * @throws AccessException
   */
  public static Acl decode(final char[] val, final String path) throws AccessException {
    EncodedAcl eacl = new EncodedAcl();
    eacl.setEncoded(val);

    Collection<Ace> aces = new ArrayList<Ace>();

    while (eacl.hasMore()) {
      Ace ace = Ace.decode(eacl, path);

      aces.add(ace);
    }

    return new Acl(aces);
  }

  /** Given an encoded acl create a new merged version. This process
   * should be carried out moving up from the end of the path to the root as
   * entries will only be added to the merged list if the notWho + whoType + who
   * do not match.
   *
   * <p>The inherited flag will be set on all merged Ace objects.
   *
   * <p>For example, if we have the path structure
   * <pre>
   *     /user                 owner=sys,access=write-content owner
   *        /jeb               owner=jeb,access=write-content owner
   *           /calendar       owner=jeb    no special access
   *           /rocalendar     owner=jeb    read owner
   * </pre>
   * then, while evaluating the access for rocalendar we start at rocalendar
   * and move up the tree. The "read owner" access on rocalendar overrides any
   * access we find further up the tree, e.g. "write-content owner"
   *
   * <p>While evaluating the access for calendar we start at calendar
   * and move up the tree. There is no overriding access so the final access is
   * "write-content owner" inherited from /user/jeb
   *
   * <p>Also note the encoded value will not reflect the eventual Acl.
   *
   * <p>And what did that mean? I think I meant that we can derive the acl for
   * an entity from the merged result.
   *
   * @param val char[] val to decode and merge
   * @param path   path of current entity to flag the inheritance
   * @return merged Acl
   * @throws AccessException
   */
  public Acl merge(final char[] val, final String path) throws AccessException {
    Collection<Ace> newAces = new ArrayList<Ace>();

    newAces.addAll(getAces());

    Acl encAcl = decode(val, path);

    domerge:
    for (Ace a: encAcl.getAces()) {
      for (Ace ace: newAces) {
        if (a.getWho().equals(ace.getWho())) {
          // Take the child entry
          continue domerge;
        }
      }

      // Not in child - add from the parent
      newAces.add(a);
    }

    return new Acl(newAces);
  }

  /* * Given a decoded acl merge it into this objects ace list. This process
   * should be carried out moving up from the end of the path to the root as
   * entries will only be added to the merged list if the notWho + whoType + who
   * do not match.
   *
   * <p>The inherited flag will be set on all merged Ace objects.
   * <p>XXX Note that reuse of Acls for merges invalidates the inherited flag.
   * I think it's only used for display and acl modification purposes so
   * shouldn't affect normal access control checks.
   *
   * <p>Also note the encoded value will not reflect the eventual Acl.
   *
   * @param val Acl to merge
   * @throws AccessException
   * /
  public void merge(Acl val) throws AccessException {
    Collection<Ace> valAces = val.getAces();

    if (valAces == null) {
      return;
    }

    for (Ace ace: valAces) {
      ace.setInherited(true);

      if (!aces.contains(ace)) {
        aces.add(ace);
      }
    }
  }*/

  /* ====================================================================
   *                 Encoding methods
   * ==================================================================== */

  /** Encode this object after manipulation or creation. Inherited entries
   * will be skipped.
   *
   * @return char[] encoded value
   * @throws AccessException
   */
  public char[] encode() throws AccessException {
    startEncoding();

    if (aces == null) {
      return null;
    }

    for (Ace ace: aces.values()) {
      if (ace.getInheritedFrom() == null) {
        ace.encode(this);
      }
    }

    return getEncoding();
  }

  /** Encode this object after manipulation or creation. Inherited entries
   * will be skipped. Returns null for no aces
   *
   * @return String encoded value or null
   * @throws AccessException
   */
  public String encodeStr() throws AccessException {
    char[] encoded = encode();
    if (encoded == null) {
       return null;
    }

    return new String(encoded);
  }

  /** Encode this object after manipulation or creation. Inherited entries
   * will NOT be skipped.
   *
   * @return char[] encoded value
   * @throws AccessException
   */
  public char[] encodeAll() throws AccessException {
    startEncoding();

    if (aces == null) {
      return null;
    }

    for (Ace ace: aces.values()) {
      ace.encode(this);
    }

    return getEncoding();
  }

  /* ====================================================================
   *                   Object methods
   * ==================================================================== */

  /** Provide a string representation for user display - this should
   * use a localized resource and be part of a display level.
   *
   * @return String representation
   */
  public String toUserString() {
    StringBuilder sb = new StringBuilder();

    try {
      decode(getEncoded());

      for (Ace ace: aces.values()) {
        sb.append(ace.toString());
        sb.append(" ");
      }
    } catch (Throwable t) {
      error(t);
      sb.append("Decode exception " + t.getMessage());
    }

    return sb.toString();
  }

  @Override
  public String toString() {
    final ToString ts = new ToString(this);

    if (!empty()) {
      rewind();
      ts.append("encoded", Arrays.asList(getEncoded()));

      rewind();

      try {
        if (aces == null) {
          decode(getEncoded());
        }

        ts.append("decoded", aces);
      } catch (Throwable t) {
        ts.append("Decode exception", t.getMessage());
      }
    }

    return ts.toString();
  }

  /** For testing
   *
   * @param args
   */
  public static void main(final String[] args) {
    try {
      Acl acl = decode(args[0]);

      System.out.println(acl.toString());
    } catch (Throwable t) {
      t.printStackTrace();
    }
  }
}

