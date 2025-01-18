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
import org.bedework.base.ToString;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/** Immutable object to represent an ace for a calendar entity or service.
 *
 * <p>The compareTo method orders the Aces according to the notWho, whoType and
 * who components. It does not take the actual privileges into account. There
 * should only be one entry per the above combination and the latest one on the
 * path should stand.
 *
 *  @author Mike Douglass   douglm   bedework.org
 */
public final class Ace
        implements PrivilegeDefs, WhoDefs, Comparable<Ace>,
        ToString.ToStringProducer {
  private final AceWho who;

  /** allowed/denied/undefined indexed by Privilege index
   */
  private PrivilegeSet how;

  /** Privilege objects defining the access. Used when manipulating acls
   */
  private final Collection<Privilege> privs;

  private final String inheritedFrom;

  /* If non-null the encoding for this ace. */
  private String encoding;

  /* If non-null the encoding as characters. */
  private char[] encodingChars;

  private static final ObjectPool<String> inheritedFroms = new ObjectPool<>();

  private static final Map<String, Ace> aceCache = new HashMap<>();

  private static final Access.AccessStatsEntry aceCacheSize =
    new Access.AccessStatsEntry("ACE cache size");

  private static final Access.AccessStatsEntry aceCacheHits =
    new Access.AccessStatsEntry("ACE cache hits");

  private static final Access.AccessStatsEntry aceCacheMisses =
    new Access.AccessStatsEntry("ACE cache misses");

  /**
   * @param who to assign access to
   * @param privs privilege set
   * @param inheritedFrom path
   * @return Ace
   */
  public static Ace makeAce(final AceWho who,
                            final Collection<Privilege> privs,
                            final String inheritedFrom) {
    final Ace ace = new Ace(who, privs, inheritedFrom);

    Ace cace = aceCache.get(ace.encoding);

    if (cace == null) {
      aceCache.put(ace.encoding, ace);
      aceCacheSize.count = aceCache.size();
      cace = ace;
    }

    return cace;
  }

  /**
   * @param who to assign access to
   * @param privs privilege set
   * @param inheritedFrom path
   */
  private Ace(final AceWho who,
              final Collection<Privilege> privs,
              final String inheritedFrom) {
    //debug = getLog().isDebugEnabled();

    this.who = who;

    how = new PrivilegeSet();
    this.privs = new ArrayList<>();
    if (privs != null) {
      for (final Privilege p: privs) {
        this.privs.add(p);
        how = PrivilegeSet.addPrivilege(how, p);
      }
    }

    if (inheritedFrom == null) {
      this.inheritedFrom = null;
    } else {
      this.inheritedFrom = inheritedFroms.get(inheritedFrom);
    }

    encode();
  }

  /** Get the access statistics
   *
   * @return Collection of stats
   */
  public static Collection<Access.AccessStatsEntry> getStatistics() {
    final Collection<Access.AccessStatsEntry> stats = new ArrayList<>();

    stats.add(aceCacheSize);
    stats.add(aceCacheHits);
    stats.add(aceCacheMisses);

    return stats;
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
   * @return PrivilegeSet array of allowed/denied/undefined indexed
   * by Privilege index
   */
  public PrivilegeSet getHow() {
    if (how == null) {
      how = new PrivilegeSet();
    }

    return how;
  }

  /**
   *
   * @return Collection of Privilege objects defining the access.
   * Used when manipulating acls
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
   * @param acl to search
   * @param cb callback to makeHref
   * @param name to find
   * @param whoType of name
   * @return PrivilegeSet    merged privileges if we find a match else null
   */
  public static PrivilegeSet findMergedPrivilege(final Acl acl,
                                                 final Access.AccessCb cb,
                                                 final String name,
                                                 final int whoType) {
    PrivilegeSet privileges = null;
    for (final Ace ace: acl.getAces()) {
      if ((whoType == ace.who.getWhoType()) &&
          ((whoType == whoTypeUnauthenticated) ||
           (whoType == whoTypeAuthenticated) ||
           (whoType == whoTypeAll) ||
           (whoType == whoTypeOwner) ||
            ace.getWho().whoMatch(cb, name))) {
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
   * @param acl to search
   * @param path If non-null flags an inherited ace
   * @return Ace access control entry
   */
  public static Ace decode(final EncodedAcl acl,
                           final String path) {
    /* Find the end of the ace and see if we have a cached version */

    final int pos = acl.getPos();

    AceWho.skip(acl);
    Privileges.skip(acl);
    acl.back();

    boolean hasInherited = false;

    if (acl.getChar() == PrivilegeDefs.inheritedFlag) {
      hasInherited = true;
      acl.skipString();
      if (acl.getChar() != ' ') {
        throw new AccessException("malformedAcl");
      }
    }

    final String enc;

    if (hasInherited || (path == null)) {
      enc = acl.getString(pos);
    } else {
      acl.back(); // Don't catch the terminating space

      final StringBuilder sb = new StringBuilder(acl.getString(pos));

      acl.getChar();  // discard terminator

      sb.append(PrivilegeDefs.inheritedFlag);
      sb.append(EncodedAcl.encodedString(path));
      sb.append(' ');

      enc = sb.toString();
    }

    //if (debug) {
    //  debugMsg("decode: string is :'" + enc + "'");
    //}

    Ace ace = aceCache.get(enc);

    if (ace != null) {
      aceCacheHits.count++;
      return ace;
    }

    aceCacheMisses.count++;

    /* Do it the hard way */
    acl.setPos(pos);

    final AceWho who = AceWho.decode(acl);

    final Collection<Privilege> privs = Privileges.getPrivs(acl);

    // See if we got an inherited flag
    acl.back();

    String inheritedFrom = null;

    if (acl.getChar() == PrivilegeDefs.inheritedFlag) {
      inheritedFrom = acl.getString();
    } else {
      acl.back();
    }

    if (acl.getChar() != ' ') {
      throw new AccessException("malformedAcl");
    }

    if (inheritedFrom == null) {
      inheritedFrom = path;  // May come from here
    }

    ace = makeAce(who, privs, inheritedFrom);

    return ace;
  }

  /* ==============================================================
   *                 Encoding methods
   * ============================================================== */

  /** Encode this object as a sequence of char. privs must have been set.
   *
   * @param acl   EncodedAcl
   */
  public void encode(final EncodedAcl acl) {
    if (encoding == null) {
      encode();
    }

    acl.addChar(encodingChars);
  }

  /** Encode this object for caching
   */
  private void encode() {
    final EncodedAcl eacl = new EncodedAcl();
    eacl.startEncoding();

    getWho().encode(eacl);

    for (final Privilege p: privs) {
      p.encode(eacl);
    }

    if (inheritedFrom != null) {
      eacl.addChar(PrivilegeDefs.inheritedFlag);
      eacl.encodeString(inheritedFrom);
    }

    eacl.addChar(' ');  // terminate privs.

    encodingChars = eacl.getEncoding();

    encoding = new String(encodingChars);
  }

  /** Provide a string representation for user display - this should probably
   * use a localized resource and be part of a display level. It also requires
   * the Privilege objects
   *
   * @return String representation
   */
  public String toUserString() {
    final StringBuilder sb = new StringBuilder("(");

    sb.append(getWho().toUserString());
    sb.append(" ");

    for (final Privilege p: privs) {
      sb.append(p.toUserString());
      sb.append(" ");
    }
    sb.append(")");

    return sb.toString();
  }

  /* ==============================================================
   *                   Object methods
   * ============================================================== */

  public int compareTo(final Ace that) {
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
    ts.append(getWho());

    if (how != null) {
      ts.append("how", how);
    }

    if (getInheritedFrom() != null) {
      ts.newLine()
        .append("inherited from ")
        .clearDelim()
        .append(getInheritedFrom());
    }

    ts.newLine().append("privs=[").clearDelim().indentIn();

    for (final Privilege p: privs) {
      ts.newLine()
        .append(p);
    }

    ts.clearDelim()
      .indentOut()
      .newLine()
      .append("]");
  }
}

