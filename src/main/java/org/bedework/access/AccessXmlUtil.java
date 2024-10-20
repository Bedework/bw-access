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

import org.bedework.util.logging.BwLogger;
import org.bedework.util.logging.Logged;
import org.bedework.util.xml.XmlEmit;
import org.bedework.util.xml.XmlUtil;
import org.bedework.util.xml.tagdefs.CaldavTags;
import org.bedework.util.xml.tagdefs.WebdavTags;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import java.io.Serializable;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/** Class to generate xml from an access specification. The resulting xml follows
 * the webdav acl spec rfc3744
 *
 *  @author Mike Douglass   douglm @ bedework.org
 *  @author Dave Brondsema
 */
public class AccessXmlUtil implements Logged, Serializable {
  private XmlEmit xml;

  private final QName[] privTags;

  /** xml privilege tags */
  public static final QName[] caldavPrivTags = {
    WebdavTags.all,              // privAll = 0;
    WebdavTags.read,             // privRead = 1;
    WebdavTags.readAcl,          // privReadAcl = 2;
    WebdavTags.readCurrentUserPrivilegeSet,  // privReadCurrentUserPrivilegeSet = 3;
    CaldavTags.readFreeBusy,     // privReadFreeBusy = 4;
    WebdavTags.write,            // privWrite = 5;
    WebdavTags.writeAcl,         // privWriteAcl = 6;
    WebdavTags.writeProperties,  // privWriteProperties = 7;
    WebdavTags.writeContent,     // privWriteContent = 8;
    WebdavTags.bind,             // privBind = 9;

    CaldavTags.schedule,         // privSchedule = 10;
    CaldavTags.scheduleRequest,  // privScheduleRequest = 11;
    CaldavTags.scheduleReply,    // privScheduleReply = 12;
    CaldavTags.scheduleFreeBusy, // privScheduleFreeBusy = 13;

    WebdavTags.unbind,           // privUnbind = 14;
    WebdavTags.unlock,           // privUnlock = 15;

    /* ----------------- CalDAV Scheduling ------------------------ */

    CaldavTags.scheduleDeliver,           //  16;
    CaldavTags.scheduleDeliverInvite,     //  17;
    CaldavTags.scheduleDeliverReply,      //  18;
    CaldavTags.scheduleQueryFreebusy,     //  19;

    CaldavTags.scheduleSend,              //  20;
    CaldavTags.scheduleSendInvite,        //  21;
    CaldavTags.scheduleSendReply,         //  22;
    CaldavTags.scheduleSendFreebusy,      //  23;

    null                         // privNone = 24;
  };

  /** Callback for xml utility
   *
   * @author douglm - bedework.org
   */
  public interface AccessXmlCb {
    /**
     * @param id account
     * @param whoType - from WhoDefs
     * @return String href
     */
    String makeHref(String id, int whoType);

    /** Return AccessPrincipal for the current principal
     *
     * @return AccessPrincipal
     * @throws AccessException on error
     */
    AccessPrincipal getPrincipal();

    /** Return AccessPrincipal for the given href
     *
     * @param href the href
     * @return AccessPrincipal or null for unknown.
     * @throws AccessException on error
     */
    AccessPrincipal getPrincipal(String href);

    /** Called during processing to indicate an error
     *
     * @param tag QNAME identifying error
     * @throws AccessException on error
     */
    void setErrorTag(QName tag);

    /** Return any error tag
     *
     * @return QName
     * @throws AccessException on error
     */
    QName getErrorTag();

    /** Called during processing to indicate an error
     *
     * @param val a message
     * @throws AccessException on error
     */
    void setErrorMsg(String val);

    /** Return any error message
     *
     * @return String or null
     * @throws AccessException on error
     */
    String getErrorMsg();
  }

  private final AccessXmlCb cb;

  /** Acls use tags in the webdav and caldav namespace.
   *
   * @param privTags the tags
   * @param xml      for emitting xml
   * @param cb       callback
   */
  public AccessXmlUtil(final QName[] privTags, final XmlEmit xml,
                       final AccessXmlCb cb) {
    if (privTags.length != PrivilegeDefs.privEncoding.length) {
      throw new RuntimeException("edu.rpi.cmt.access.BadParameter");
    }

    this.privTags = privTags;
    this.xml = xml;
    this.cb = cb;
  }

  /** Represent the acl as an xml string
   *
   * @param acl the ACL object
   * @param forWebDAV  - true if we should split deny from grant.
   * @param privTags the tags
   * @param cb       callback
   * @return String xml representation
   */
  public static String getXmlAclString(final Acl acl, final boolean forWebDAV,
                                       final QName[] privTags,
                                       final AccessXmlCb cb) {
    try {
      final XmlEmit xml = new XmlEmit(true);  // no headers
      final StringWriter su = new StringWriter();
      xml.startEmit(su);
      final AccessXmlUtil au = new AccessXmlUtil(privTags, xml, cb);

      au.emitAcl(acl, forWebDAV);

      su.close();

      return su.toString();
    } catch (final AccessException ae) {
      throw ae;
    } catch (final Throwable t) {
      throw new AccessException(t);
    }
  }

  /** (Re)set the xml writer
   *
   * @param val      xml Writer
   */
  public void setXml(final XmlEmit val) {
    xml = val;
  }

  /** Return any error tag
   *
   * @return QName
   * @throws AccessException on error
   */
  public QName getErrorTag() {
    return cb.getErrorTag();
  }

  /** Return any error message
   *
   * @return String or null
   * @throws AccessException on error
   */
  public String getErrorMsg() {
    return cb.getErrorMsg();
  }

  /** Given a webdav like xml acl return the internalized form as an Acl.
   *
   * @param xmlStr the XML string form
   * @param setting - true if we are being called to set a value
   * @return Acl
   */
  public Acl getAcl(final String xmlStr,
                    final boolean setting) {
    try {
      final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);

      final DocumentBuilder builder = factory.newDocumentBuilder();

      final Document doc = builder.parse(new InputSource(new StringReader(xmlStr)));

      return getAcl(doc.getDocumentElement(), setting);
    } catch (final AccessException ae) {
      throw ae;
    } catch (final Throwable t) {
      throw new AccessException(t);
    }
  }

  /**
   * @param root parsed XML root element
   * @param setting - true if we are being called to set a value
   * @return Acl
   */
  public Acl getAcl(final Element root,
                    final boolean setting) {
    try {
      /* We expect an acl root element containing 0 or more ace elements
       <!ELEMENT acl (ace)* >
       */
      if (!XmlUtil.nodeMatches(root, WebdavTags.acl)) {
        throw exc("Expected ACL");
      }

      final Element[] aceEls = XmlUtil.getElementsArray(root);

      final Collection<ParsedAce> paces = new ArrayList<>();

      for (final Element curnode: aceEls) {
        if (!XmlUtil.nodeMatches(curnode, WebdavTags.ace)) {
          throw exc("Expected ACE");
        }

        final ParsedAce pace = processAce(curnode, setting);
        if (pace == null) {
          break;
        }

        //if (debug() && (pace._protected)) {
       // }

        //if (debug() && (pace.inheritedFrom != null)) {
        //}

        /* Look for this 'who' in the list */

        for (final ParsedAce pa: paces) {
          if (pa.ace.getWho().equals(pace.ace.getWho()) &&
              (pa.deny == pace.deny)) {
            throw exc("Multiple ACEs for " + pa.ace.getWho());
          }
        }

        paces.add(pace);
      }

      final Collection<Ace> aces = new ArrayList<>();

      for (final ParsedAce pa: paces) {
        if (pa.deny) {
          aces.add(pa.ace);
        }
      }

      for (final ParsedAce pa: paces) {
        if (!pa.deny) {
          aces.add(pa.ace);
        }
      }

      return new Acl(aces);
    } catch (final AccessException ae) {
      throw ae;
    } catch (final Throwable t) {
      error(t);
      throw new AccessException(t);
    }
  }

  /**
   * Emit an acl as an xml string using the current xml writer
   *
   * @param acl the ACL object
   * @param forWebDAV  - true if we should split deny from grant.
   */
  public void emitAcl(final Acl acl, final boolean forWebDAV) {
    try {
      emitAces(acl.getAces(), forWebDAV);
    } catch (final AccessException ae) {
      throw ae;
    } catch (final Throwable t) {
      throw new AccessException(t);
    }
  }

  /** Produce an xml representation of supported privileges. This is the same
   * at all points in the system and is identical to the webdav/caldav
   * requirements.
   *
   */
  public void emitSupportedPrivSet() {
    try {
      xml.openTag(WebdavTags.supportedPrivilegeSet);

      emitSupportedPriv(Privileges.getPrivAll());

      xml.closeTag(WebdavTags.supportedPrivilegeSet);
    } catch (final Throwable t) {
      throw new AccessException(t);
    }
  }

  /** Produce an xml representation of current user privileges from an array
   * of allowed/disallowed/unspecified flags indexed by a privilege index.
   *
   * <p>Each position i in privileges corrsponds to a privilege defined by
   * privTags[i].
   *
   * @param xml to emit
   * @param privTags the tags
   * @param privileges    char[] of allowed/disallowed
   */
  public static void emitCurrentPrivSet(final XmlEmit xml,
                                        final QName[] privTags,
                                        final char[] privileges) {
    if (privTags.length != PrivilegeDefs.privEncoding.length) {
      throw new AccessException("edu.rpi.cmt.access.BadParameter");
    }

    try {
      xml.openTag(WebdavTags.currentUserPrivilegeSet);

      for (int pi = 0; pi < privileges.length; pi++) {
        if ((privileges[pi] == PrivilegeDefs.allowed) ||
            (privileges[pi] == PrivilegeDefs.allowedInherited)) {
          // XXX further work - don't emit abstract privs or contained privs.
          final QName pr = privTags[pi];

          if (pr != null) {
            xml.propertyTagVal(WebdavTags.privilege, pr);
          }
        }
      }

      xml.closeTag(WebdavTags.currentUserPrivilegeSet);
    } catch (final Throwable t) {
      throw new AccessException(t);
    }
  }

  /** Produce an xml representation of current user privileges from an array
   * of allowed/disallowed/unspecified flags indexed by a privilege index,
   * returning the representation a a String
   *
   * @param privTags the tags
   * @param ps    PrivilegeSet allowed/disallowed
   * @return String xml
   */
  public static String getCurrentPrivSetString(final QName[] privTags,
                                               final PrivilegeSet ps) {
    try {
      final char[] privileges = ps.getPrivileges();

      final XmlEmit xml = new XmlEmit(true);  // no headers
      final StringWriter su = new StringWriter();
      xml.startEmit(su);
      AccessXmlUtil.emitCurrentPrivSet(xml, privTags, privileges);

      su.close();

      return su.toString();
    } catch (final AccessException ae) {
      throw ae;
    } catch (final Throwable t) {
      throw new AccessException(t);
    }
  }

  /* ==============================================================
   *                   Private methods
   * ============================================================== */

  private static class ParsedAce {
    Ace ace;
    boolean deny;
    boolean _protected;
    String inheritedFrom;

    ParsedAce(final Ace ace,
              final boolean deny,
              final boolean _protected,
              final String inheritedFrom) {
      this.ace = ace;
      this.deny = deny;
      this._protected = _protected;
      this.inheritedFrom = inheritedFrom;
    }
  }

  /** Process an acl<br/>
         <!ELEMENT ace ((principal | invert), (grant|deny), protected?,
                         inherited?)>
         <!ELEMENT grant (privilege+)>
         <!ELEMENT deny (privilege+)>

         protected is for acl display only
   *
   * @param nd representing an ACE
   * @param setting - true if we are being called to set a value
   * @return ParsedAce object
   */
  private ParsedAce processAce(final Node nd,
                               final boolean setting) {
    final Element[] children = XmlUtil.getElementsArray(nd);
    int pos = 0;

    if (children.length < 2) {
      throw exc("Bad ACE");
    }

    Element curnode = children[pos];
    boolean inverted = false;
    boolean _protected = false;
    String inheritedFrom = null;

    /* Require principal or invert */

    if (XmlUtil.nodeMatches(curnode, WebdavTags.invert)) {
      /*  <!ELEMENT invert principal>       */

      inverted = true;
      curnode = XmlUtil.getOnlyElement(curnode);
    }

    final AceWho awho = parseAcePrincipal(curnode, inverted);

    if (awho == null) {
      return null;
    }

    pos++;
    curnode = children[pos];

    /* grant or deny required here */
    final Privs privs = parseGrantDeny(curnode);

    if (privs == null) {
      if (debug()) {
        debug("Expected grant | deny");
      }
      cb.setErrorTag(WebdavTags.noAceConflict);
      return null;
    }

    pos++;

    /* possible protected */
    if (pos < children.length) {
      curnode = children[pos];

      if (XmlUtil.nodeMatches(curnode, WebdavTags._protected)) {
        if (setting) {
          if (debug()) {
            debug("protected element when setting acls.");
          }
          cb.setErrorTag(WebdavTags.noAceConflict);
          return null;
        }

        _protected = true;
        pos++;
      }
    }

    /* possible inherited */
    if (pos < children.length) {
      curnode = children[pos];
      if (XmlUtil.nodeMatches(curnode, WebdavTags.inherited)) {
        if (setting) {
          if (debug()) {
            debug("inherited element when setting acls.");
          }
          cb.setErrorTag(WebdavTags.noAceConflict);
          return null;
        }

        curnode = XmlUtil.getOnlyElement(curnode);

        if (!XmlUtil.nodeMatches(curnode, WebdavTags.href)) {
          throw exc("Missing inherited href");
        }

        final String href = XmlUtil.getElementContent(curnode);

        if ((href == null) || (href.isEmpty())) {
          throw exc("Missing inherited href");
        }

        inheritedFrom = href;
        pos++;
      }
    }

    if (pos < children.length) {
      throw exc("Unexpected element " + children[pos]);
    }

    return new ParsedAce(Ace.makeAce(awho, privs.privs, inheritedFrom),
                         privs.deny, _protected, inheritedFrom);
  }

  private AceWho parseAcePrincipal(final Node nd,
                                   final boolean inverted) {
    if (!XmlUtil.nodeMatches(nd, WebdavTags.principal)) {
      throw exc("Bad ACE - expect principal");
    }

    Element el = XmlUtil.getOnlyElement(nd);

    final int whoType;
    String who = null;

    if (XmlUtil.nodeMatches(el, WebdavTags.href)) {
      final String href = XmlUtil.getElementContent(el);

      if ((href == null) || (href.isEmpty())) {
        throw exc("Missing href");
      }

      final AccessPrincipal ap = cb.getPrincipal(href);

      if (ap == null) {
        cb.setErrorTag(WebdavTags.recognizedPrincipal);
        cb.setErrorMsg(href);
        return null;
      }

      whoType = ap.getKind();
      who = ap.getAclAccount();
    } else if (XmlUtil.nodeMatches(el, WebdavTags.all)) {
      whoType = Ace.whoTypeAll;
    } else if (XmlUtil.nodeMatches(el, WebdavTags.authenticated)) {
      whoType = Ace.whoTypeAuthenticated;
    } else if (XmlUtil.nodeMatches(el, WebdavTags.unauthenticated)) {
      whoType = Ace.whoTypeUnauthenticated;
    } else if (XmlUtil.nodeMatches(el, WebdavTags.property)) {
      el = XmlUtil.getOnlyElement(el);
      if (XmlUtil.nodeMatches(el, WebdavTags.owner)) {
        whoType = Ace.whoTypeOwner;
      } else {
        throw exc("Bad WHO property");
      }
    } else if (XmlUtil.nodeMatches(el, WebdavTags.self)) {
      whoType = cb.getPrincipal().getKind();
      who = cb.getPrincipal().getAccount();
    } else {
      throw exc("Bad WHO");
    }

    final AceWho awho = AceWho.getAceWho(who, whoType, inverted);

    if (debug()) {
      debug("Parsed ace/principal =" + awho);
    }

    return awho;
  }

  private static class Privs {
    Collection<Privilege> privs;
    boolean deny;

    Privs(final Collection<Privilege> privs,
          final boolean deny) {
      this.privs = privs;
      this.deny = deny;
    }
  }

  private Privs parseGrantDeny(final Node nd) {
    boolean denial = false;

    if (XmlUtil.nodeMatches(nd, WebdavTags.deny)) {
      denial = true;
    } else if (!XmlUtil.nodeMatches(nd, WebdavTags.grant)) {
      return null;
    }

    final Collection<Privilege> privs = new ArrayList<>();
    final Element[] pchildren = XmlUtil.getElementsArray(nd);

    for (final Element pnode: pchildren) {
      if (!XmlUtil.nodeMatches(pnode, WebdavTags.privilege)) {
        throw exc("Bad ACE - expect privilege");
      }

      privs.add(parsePrivilege(pnode, denial));
    }

    return new Privs(privs, denial);
  }

  private Privilege parsePrivilege(final Node nd,
                                   final boolean denial) {
    final Element el = XmlUtil.getOnlyElement(nd);

    int priv;

    findPriv: {
      // ENUM
      for (priv = 0; priv < privTags.length; priv++) {
        if (XmlUtil.nodeMatches(el, privTags[priv])) {
          break findPriv;
        }
      }
      throw exc("Bad privilege");
    }

    if (debug()) {
      debug("Add priv " + priv + " denied=" + denial);
    }

    return Privileges.makePriv(priv, denial);
  }

  /* Emit the Collection of aces as an xml using the current xml writer
   *
   * @param aces
   * @throws AccessException
   */
  private void emitAces(final Collection<Ace> aces,
                        final boolean forWebDAV) {
    try {
      xml.openTag(WebdavTags.acl);

      if (aces != null) {
        for (final Ace ace: aces) {
          boolean aceOpen = emitAce(ace, false, false);

          if (aceOpen && forWebDAV) {
            closeAce(ace);
            aceOpen = false;
          }

          if (emitAce(ace, true, aceOpen)) {
            aceOpen = true;
          }

          if (aceOpen) {
            closeAce(ace);
          }
        }
      }

      xml.closeTag(WebdavTags.acl);
    } catch (final AccessException ae) {
      throw ae;
    } catch (final Throwable t) {
      throw new AccessException(t);
    }
  }

  private void closeAce(final Ace ace) {
    if (ace.getInheritedFrom() != null) {
      final QName tag = WebdavTags.inherited;
      xml.openTag(tag);
      xml.property(WebdavTags.href, ace.getInheritedFrom());
      xml.closeTag(tag);
    }
    xml.closeTag(WebdavTags.ace);
  }

  private void emitSupportedPriv(final Privilege priv) {
    xml.openTag(WebdavTags.supportedPrivilege);

    xml.openTagNoNewline(WebdavTags.privilege);
    xml.emptyTagSameLine(privTags[priv.getIndex()]);
    xml.closeTagNoblanks(WebdavTags.privilege);

    if (priv.getAbstractPriv()) {
      xml.emptyTag(WebdavTags._abstract);
    }

    xml.property(WebdavTags.description, priv.getDescription());

    for (final Privilege p: priv.getContainedPrivileges()) {
      emitSupportedPriv(p);
    }

    xml.closeTag(WebdavTags.supportedPrivilege);
  }

  /* This gets called twice, once to do denials, once to do grants
   *
   */
  private boolean emitAce(final Ace ace,
                          final boolean denials,
                          boolean aceOpen) {
    boolean tagOpen = false;

    final QName tag;
    if (denials) {
      tag = WebdavTags.deny;
    } else {
      tag = WebdavTags.grant;
    }

    for (final Privilege p: ace.getPrivs()) {
      if (denials == p.getDenial()) {
        if (!aceOpen) {
          xml.openTag(WebdavTags.ace);

          emitAceWho(ace.getWho());
          aceOpen = true;
        }

        if (!tagOpen) {
          xml.openTag(tag);
          tagOpen = true;
        }

        xml.propertyTagVal(WebdavTags.privilege, privTags[p.getIndex()]);
      }
    }

    if (tagOpen) {
      xml.closeTag(tag);
    }

    return aceOpen;
  }

  private void emitAceWho(final AceWho who) {
    boolean invert = who.getNotWho();

    if (who.getWhoType() == Ace.whoTypeOther) {
      invert = !invert;
    }

    if (invert) {
      xml.openTag(WebdavTags.invert);
    }

    xml.openTag(WebdavTags.principal);

    final int whoType = who.getWhoType();

    /*
           <!ELEMENT principal (href)
                  | all | authenticated | unauthenticated
                  | property | self)>
    */

    if ((whoType == Ace.whoTypeOwner) ||
        (whoType == Ace.whoTypeOther)) {
      // Other is !owner
      xml.openTag(WebdavTags.property);
      xml.emptyTag(WebdavTags.owner);
      xml.closeTag(WebdavTags.property);
    } else if (whoType == Ace.whoTypeUnauthenticated) {
      xml.emptyTag(WebdavTags.unauthenticated);
    } else if (whoType == Ace.whoTypeAuthenticated) {
      xml.emptyTag(WebdavTags.authenticated);
    } else if (whoType == Ace.whoTypeAll) {
      xml.emptyTag(WebdavTags.all);
    } else  {
      /* Just emit href */
      final String href = escapeChars(cb.makeHref(who.getWho(), whoType));
      xml.property(WebdavTags.href, href);
    }

    xml.closeTag(WebdavTags.principal);

    if (invert) {
      xml.closeTag(WebdavTags.invert);
    }
  }

  /**
   * Lifted from org.apache.struts.util.ResponseUtils#filter
   * <br/>
   * Filter the specified string for characters that are senstive to HTML
   * interpreters, returning the string with these characters replaced by the
   * corresponding character entities.
   *
   * @param value      The string to be filtered and returned
   * @return String   escaped value
   */
  public static String escapeChars(final String value) {
    if ((value == null) || (value.isEmpty())) {
      return value;
    }

    StringBuilder result = null;
    String filtered;

    for (int i = 0; i < value.length(); i++) {
      filtered = switch (value.charAt(i)) {
        case '<' -> "&lt;";
        case '>' -> "&gt;";
        case '&' -> "&amp;";
        case '"' -> "&quot;";
        case '\'' -> "&#39;";
        default -> null;
      };

      if (result == null) {
        if (filtered != null) {
          result = new StringBuilder(value.length() + 50);

          if (i > 0) {
            result.append(value, 0, i);
          }

          result.append(filtered);
        }
      } else if (filtered == null) {
        result.append(value.charAt(i));
      } else {
        result.append(filtered);
      }
    }

    if (result == null) {
      return value;
    }

    return result.toString();
  }

  private AccessException exc(final String msg) {
    if (debug()) {
      debug(msg);
    }
    return AccessException.badXmlACL(msg);
  }

  /* ==============================================================
   *                   Logged methods
   * ============================================================== */

  private final BwLogger logger = new BwLogger();

  @Override
  public BwLogger getLogger() {
    if ((logger.getLoggedClass() == null) && (logger.getLoggedName() == null)) {
      logger.setLoggedClass(getClass());
    }

    return logger;
  }
}
