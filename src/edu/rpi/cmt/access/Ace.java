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
import edu.rpi.cmt.access.Access.AccessStatsEntry;
import edu.rpi.sss.util.ObjectPool;

import org.apache.log4j.Logger;

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
 *  @author Mike Douglass   douglm   rpi.edu
 */
public final class Ace implements PrivilegeDefs, WhoDefs, Comparable<Ace> {
  //private static boolean debug;

  private static transient Logger log;

  private AceWho who;

  /** allowed/denied/undefined indexed by Privilege index
   */
  private PrivilegeSet how;

  /** Privilege objects defining the access. Used when manipulating acls
   */
  private Collection<Privilege> privs;

  private String inheritedFrom;

  /* If non-null the encoding for this ace. */
  private String encoding;

  /* If non-null the encoding as characters. */
  private char[] encodingChars;

  private static ObjectPool<String> inheritedFroms = new ObjectPool<String>();

  private static Map<String, Ace> aceCache = new HashMap<String, Ace>();

  private static AccessStatsEntry aceCacheSize =
    new AccessStatsEntry("ACE cache size");

  private static AccessStatsEntry aceCacheHits =
    new AccessStatsEntry("ACE cache hits");

  private static AccessStatsEntry aceCacheMisses =
    new AccessStatsEntry("ACE cache misses");

  /**
   * @param who
   * @param privs
   * @param inheritedFrom
   * @return Ace
   * @throws AccessException
   */
  public static Ace makeAce(final AceWho who,
                            final Collection<Privilege> privs,
                            final String inheritedFrom) throws AccessException {
    Ace ace = new Ace(who, privs, inheritedFrom);

    Ace cace = aceCache.get(ace.encoding);

    if (cace == null) {
      aceCache.put(ace.encoding, ace);
      aceCacheSize.count = aceCache.size();
      cace = ace;
    }

    return cace;
  }

  /**
   * @param who
   * @param privs
   * @param inheritedFrom
   * @throws AccessException
   */
  private Ace(final AceWho who,
              final Collection<Privilege> privs,
              final String inheritedFrom) throws AccessException {
    //debug = getLog().isDebugEnabled();

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

    encode();
  }

  /** Get the access statistics
   *
   * @return Collection of stats
   */
  public static Collection<AccessStatsEntry> getStatistics() {
    Collection<AccessStatsEntry> stats = new ArrayList<AccessStatsEntry>();

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
   * @param cb
   * @param name
   * @param whoType
   * @return PrivilegeSet    merged privileges if we find a match else null
   * @throws AccessException
   */
  public static PrivilegeSet findMergedPrivilege(Acl acl,
                                                 AccessCb cb,
                                                 String name,
                                                 int whoType) throws AccessException {
    PrivilegeSet privileges = null;
    for (Ace ace: acl.getAces()) {
      if ((whoType == ace.who.getWhoType()) &&
          ((whoType == AceWho.whoTypeUnauthenticated) ||
           (whoType == AceWho.whoTypeAuthenticated) ||
           (whoType == AceWho.whoTypeAll) ||
           (whoType == AceWho.whoTypeOwner) ||
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
   * @param acl
   * @param path If non-null flags an inherited ace
   * @return Ace
   * @throws AccessException
   */
  public static Ace decode(EncodedAcl acl,
                           String path) throws AccessException {
    /* Find the end of the ace and see if we have a cached version */

    int pos = acl.getPos();

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

    String enc;

    if (hasInherited || (path == null)) {
      enc = acl.getString(pos);
    } else {
      acl.back(); // Don't catch the terminating space

      StringBuilder sb = new StringBuilder(acl.getString(pos));

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

    AceWho who = AceWho.decode(acl);

    Collection<Privilege> privs = Privileges.getPrivs(acl);

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

  /* ====================================================================
   *                 Encoding methods
   * ==================================================================== */

  /** Encode this object as a sequence of char. privs must have been set.
   *
   * @param acl   EncodedAcl
   * @throws AccessException
   */
  public void encode(EncodedAcl acl) throws AccessException {
    if (encoding == null) {
      encode();
    }

    acl.addChar(encodingChars);
  }

  /** Encode this object for caching
   *
   * @throws AccessException
   */
  private void encode() throws AccessException {
    EncodedAcl eacl = new EncodedAcl();
    eacl.startEncoding();

    getWho().encode(eacl);

    for (Privilege p: privs) {
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
   *                   private methods
   * ==================================================================== */

  protected static Logger getLog() {
    if (log == null) {
      log = Logger.getLogger(Ace.class);
    }

    return log;
  }

  protected static void debugMsg(String msg) {
    getLog().debug(msg);
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
      sb.append(", \ninherited from \"");
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

