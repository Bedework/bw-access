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

import org.bedework.util.logging.Logged;
import org.bedework.util.misc.ToString;

import java.io.CharArrayWriter;
import java.io.Serializable;

/** Object to represent an encoded acl for a calendar entity or service.
 *
 *  @author Mike Douglass   douglm@bedework.org
 */
public class EncodedAcl implements Serializable, Logged {
  /** We represent the acl as a sequence of characters which we try to
      process with the minimum of overhead.
   */
  private char[] encoded;

  /** Current position in the acl */
  private int pos;

  /* When encoding an acl we build it here.
   */
  private transient CharArrayWriter caw;

  private static final String[] encodedLengths;

  static {
    encodedLengths = new String[200];

    for (int i = 0; i < encodedLengths.length; i++) {
      encodedLengths[i] = intEncodedLength(i);
    }
  }

  /** Set an encoded value
   *
   * @param val char[] encoded value
   */
  public void setEncoded(char[] val) {
    encoded = val;
    pos = 0;
  }

  /** Get the encoded value
   *
   * @return char[] encoded value
   */
  public char[] getEncoded() {
    return encoded;
  }

  /** Provide segment of input for debugging and errors
   *
   * @return String segment
   */
  public String getErrorInfo() {
    StringBuffer sb = new StringBuffer();

    sb.append("at ");
    sb.append(pos - 1);
    sb.append(" in '");
    sb.append(encoded);
    sb.append("'");

    return sb.toString();
  }

  /* ====================================================================
   *                 Decoding methods
   * ==================================================================== */

  /** Get next char from encoded value. Return < 0 for no more
   *
   * @return char value
   */
  public char getChar() {
    if ((encoded == null) || (pos == encoded.length)) {
      if (debug()) {
        debug("getChar=-1");
      }
      return (char)-1;
    }

    char c = encoded[pos];
    if (debug()) {
      debug("getChar='" + c + "'");
    }
    pos++;

    return c;
  }

  /** Back off one char
   *
   * @throws AccessException
   */
  public void back() throws AccessException {
    back(1);
  }

  /** Back off n chars
   *
   * @param n   int number of chars
   * @throws AccessException
   */
  public void back(int n) throws AccessException {
    if (pos - n < 0) {
      throw AccessException.badACLRewind();
    }

    pos -= n;

    if (debug()) {
      debug("pos back to " + pos);
    }
  }

  /** Get current position
   *
   * @return int position
   */
  public int getPos() {
    return pos;
  }

  /** Set current position
   *
   * @param val  int position
   */
  public void setPos(int val) {
    pos = val;

    if (debug()) {
      debug("set pos to " + pos);
    }
  }

  /** Rewind to the start
   */
  public void rewind() {
    pos = 0;

    if (debug()) {
      debug("rewind");
    }
  }

  /** Get number of chars remaining
   *
   * @return int number of chars remaining
   */
  public int remaining() {
    if (encoded == null) {
      return 0;
    }
    return encoded.length - pos;
  }

  /** Test for more
   *
   * @return boolean true for more
   */
  public boolean hasMore() {
    return remaining() > 0;
  }

  /** Test for no more
   *
   * @return boolean true for no more
   */
  public boolean empty() {
    return (encoded == null) || (encoded.length == 0);
  }

  /** Return the value of a blank terminated length. On success current pos
   * has been incremented.
   *
   * @return int length
   * @throws AccessException
   */
  public int getLength() throws AccessException {
    int res = 0;

    for (;;) {
      char c = getChar();
      if (c == ' ') {
        break;
      }

      if (c < 0) {
        throw AccessException.badACLLength();
      }

      if ((c < '0') || (c > '9')) {
        throw AccessException.badACL("digit=" + c);
      }

      res = res * 10 + Character.digit(c, 10);
    }

    return res;
  }

  /** Get a String from the encoded acl at the current position.
   *
   * @return String decoded String value
   * @throws AccessException
   */
  public String getString() throws AccessException {
    if (getChar() == 'N') {
      return null;
    }
    back();
    int len = getLength();

    if ((encoded.length - pos) < len) {
      throw AccessException.badACLLength();
    }

    String s = new String(encoded, pos, len);
    pos += len;

    return s;
  }

  /** Skip a String from the encoded acl at the current position.
   *
   * @throws AccessException
   */
  public void skipString() throws AccessException {
    if (getChar() == 'N') {
      return;
    }

    back();
    int len = getLength();
    pos += len;
  }

  /** Get a String from the encoded acl at the given position and length.
   *
   * @param begin
   * @return String value
   * @throws AccessException
   */
  public String getString(int begin) throws AccessException {
    return new String(encoded, begin, pos - begin);
  }

  /* ====================================================================
   *                 Encoding methods
   * ==================================================================== */

  /** Get ready to encode
   *
   */
  public void startEncoding() {
    caw = new CharArrayWriter();
  }

  /** Encode a blank terminated 0 prefixed length.
   *
   * @param len
   * @throws AccessException
   */
  public void encodeLength(int len) throws AccessException {
    try {
      if (len < encodedLengths.length) {
        caw.write(encodedLengths[len]);
        return;
      }

      String slen = String.valueOf(len);
      caw.write('0');
      caw.write(slen, 0, slen.length());
      caw.write(' ');
    } catch (Throwable t) {
      throw new AccessException(t);
    }
  }

  /** Produce string encoding of length
   *
   * @param len
   * @return String
   */
  public static String encodedLength(int len) {
    if (len < encodedLengths.length) {
      return encodedLengths[len];
    }

    return intEncodedLength(len);
  }

  private static String intEncodedLength(int len) {
    StringBuilder sb = new StringBuilder();

    sb.append('0');
    sb.append(len);
    sb.append(' ');

    return sb.toString();
  }

  /** Encode a String with length prefix. String is encoded as <ul>
   * <li>One byte 'N' for null string or</li>
   * <li>length {@link #encodeLength(int)} followed by</li>
   * <li>String value.</li>
   * </ul>
   *
   * @param val
   * @throws AccessException
   */
  public void encodeString(String val) throws AccessException {
    try {
      if (val == null) {
        caw.write('N'); // flag null
      } else {
        encodeLength(val.length());
        caw.write(val, 0, val.length());
      }
    } catch (AccessException ae) {
      throw ae;
    } catch (Throwable t) {
      throw new AccessException(t);
    }
  }

  /**
   * @param val
   * @return String encoding.
   */
  public static String encodedString(String val) {
    if (val == null) {
      return "N";
    }

    StringBuilder sb = new StringBuilder(encodedLength(val.length()));
    sb.append(val);

    return sb.toString();
  }

  /** Add a character
   *
   * @param c char
   * @throws AccessException
   */
  public void addChar(char c) throws AccessException {
    try {
      caw.write(c);
    } catch (Throwable t) {
      throw new AccessException(t);
    }
  }

  /** Add an array of character
   *
   * @param c char[]
   * @throws AccessException
   */
  public void addChar(char[] c) throws AccessException {
    try {
      caw.write(c);
    } catch (Throwable t) {
      throw new AccessException(t);
    }
  }

  /** Get the current encoded value
   *
   * @return char[] encoded value
   */
  public char[] getEncoding() {
    char[] enc = caw.toCharArray();
    caw = null;
    if ((enc == null) || (enc.length == 0)) {
      return null;
    }

    return enc;
  }

  /* ====================================================================
   *                   Object methods
   * ==================================================================== */

  public String toString() {
    final ToString ts = new ToString(this);

    ts.append("pos", pos);

    return ts.toString();
  }
}

