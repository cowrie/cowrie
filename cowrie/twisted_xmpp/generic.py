# -*- test-case-name: wokkel.test.test_generic -*-
#
# Copyright (c) Ralph Meijer.
# See LICENSE for details.

"""
Generic XMPP protocol helpers.
"""

from __future__ import division, absolute_import

from zope.interface import implementer

from twisted.internet import defer, protocol
from twisted.python import reflect
from twisted.python.deprecate import deprecated
from twisted.python.versions import Version
from twisted.words.protocols.jabber import error, jid, xmlstream
from twisted.words.protocols.jabber.xmlstream import toResponse
from twisted.words.xish import domish, utility
from twisted.words.xish.xmlstream import BootstrapMixin

from cowrie.twisted_xmpp.iwokkel import IDisco
from cowrie.twisted_xmpp.subprotocols import XMPPHandler

IQ_GET = '/iq[@type="get"]'
IQ_SET = '/iq[@type="set"]'

NS_VERSION = 'jabber:iq:version'
VERSION = IQ_GET + '/query[@xmlns="' + NS_VERSION + '"]'

def parseXml(string):
    """
    Parse serialized XML into a DOM structure.

    @param string: The serialized XML to be parsed, UTF-8 encoded.
    @type string: C{str}.
    @return: The DOM structure, or C{None} on empty or incomplete input.
    @rtype: L{domish.Element}
    """
    roots = []
    results = []
    elementStream = domish.elementStream()
    elementStream.DocumentStartEvent = roots.append
    elementStream.ElementEvent = lambda elem: roots[0].addChild(elem)
    elementStream.DocumentEndEvent = lambda: results.append(roots[0])
    elementStream.parse(string)
    return results and results[0] or None



def stripNamespace(rootElement):
    namespace = rootElement.uri

    def strip(element):
        if element.uri == namespace:
            element.uri = None
            if element.defaultUri == namespace:
                element.defaultUri = None
            for child in element.elements():
                strip(child)

    if namespace is not None:
        strip(rootElement)

    return rootElement



class FallbackHandler(XMPPHandler):
    """
    XMPP subprotocol handler that catches unhandled iq requests.

    Unhandled iq requests are replied to with a service-unavailable stanza
    error.
    """

    def connectionInitialized(self):
        self.xmlstream.addObserver(IQ_SET, self.iqFallback, -1)
        self.xmlstream.addObserver(IQ_GET, self.iqFallback, -1)

    def iqFallback(self, iq):
        if iq.handled == True:
            return

        reply = error.StanzaError('service-unavailable')
        self.xmlstream.send(reply.toResponse(iq))



@implementer(IDisco)
class VersionHandler(XMPPHandler):
    """
    XMPP subprotocol handler for XMPP Software Version.

    This protocol is described in
    U{XEP-0092<http://xmpp.org/extensions/xep-0092.html>}.
    """

    def __init__(self, name, version):
        self.name = name
        self.version = version

    def connectionInitialized(self):
        self.xmlstream.addObserver(VERSION, self.onVersion)

    def onVersion(self, iq):
        response = toResponse(iq, "result")

        query = response.addElement((NS_VERSION, "query"))
        query.addElement("name", content=self.name)
        query.addElement("version", content=self.version)
        self.send(response)

        iq.handled = True

    def getDiscoInfo(self, requestor, target, nodeIdentifier=''):
        info = set()

        if not nodeIdentifier:
            from wokkel import disco
            info.add(disco.DiscoFeature(NS_VERSION))

        return defer.succeed(info)

    def getDiscoItems(self, requestor, target, nodeIdentifier=''):
        return defer.succeed([])



class XmlPipe(object):
    """
    XML stream pipe.

    Connects two objects that communicate stanzas through an XML stream like
    interface. Each of the ends of the pipe (sink and source) can be used to
    send XML stanzas to the other side, or add observers to process XML stanzas
    that were sent from the other side.

    XML pipes are usually used in place of regular XML streams that are
    transported over TCP. This is the reason for the use of the names source
    and sink for both ends of the pipe. The source side corresponds with the
    entity that initiated the TCP connection, whereas the sink corresponds with
    the entity that accepts that connection. In this object, though, the source
    and sink are treated equally.

    Unlike Jabber
    L{XmlStream<twisted.words.protocols.jabber.xmlstream.XmlStream>}s, the sink
    and source objects are assumed to represent an eternal connected and
    initialized XML stream. As such, events corresponding to connection,
    disconnection, initialization and stream errors are not dispatched or
    processed.

    @ivar source: Source XML stream.
    @ivar sink: Sink XML stream.
    """

    def __init__(self):
        self.source = utility.EventDispatcher()
        self.sink = utility.EventDispatcher()
        self.source.send = lambda obj: self.sink.dispatch(obj)
        self.sink.send = lambda obj: self.source.dispatch(obj)



class Stanza(object):
    """
    Abstract representation of a stanza.

    @ivar sender: The sending entity.
    @type sender: L{jid.JID}
    @ivar recipient: The receiving entity.
    @type recipient: L{jid.JID}
    """

    recipient = None
    sender = None
    stanzaKind = None
    stanzaID = None
    stanzaType = None

    def __init__(self, recipient=None, sender=None):
        self.recipient = recipient
        self.sender = sender


    @classmethod
    def fromElement(Class, element):
        """
        Create a stanza from a L{domish.Element}.
        """
        stanza = Class()
        stanza.parseElement(element)
        return stanza


    def parseElement(self, element):
        """
        Parse the stanza element.

        This is called with the stanza's element when a L{Stanza} is
        created using L{fromElement}. It parses the stanza's core attributes
        (addressing, type and id), strips the namespace from the stanza
        element for easier transport across streams and passes on
        child elements for further parsing.

        Child element parsers are defined by providing a C{childParsers}
        attribute on a subclass, as a mapping from (URI, name) to the name
        of the handler on C{self}. C{parseElement} will accumulate
        C{childParsers} from its class hierarchy, iterate over the child
        elements and pass it to matching handlers based on the child element's
        URI and name. The special key of C{None} can be used to pass all
        child elements to.
        """
        if element.hasAttribute('from'):
            self.sender = jid.internJID(element['from'])
        if element.hasAttribute('to'):
            self.recipient = jid.internJID(element['to'])
        self.stanzaType = element.getAttribute('type')
        self.stanzaID = element.getAttribute('id')

        # Save element
        stripNamespace(element)
        self.element = element

        # accumulate all childHandlers in the class hierarchy of Class 
        handlers = {}
        reflect.accumulateClassDict(self.__class__, 'childParsers', handlers)

        for child in element.elements():
            try:
                handler = handlers[child.uri, child.name]
            except KeyError:
                try:
                    handler = handlers[None]
                except KeyError:
                    continue

            getattr(self, handler)(child)


    def toElement(self):
        element = domish.Element((None, self.stanzaKind))
        if self.sender is not None:
            element['from'] = self.sender.full()
        if self.recipient is not None:
            element['to'] = self.recipient.full()
        if self.stanzaType:
            element['type'] = self.stanzaType
        if self.stanzaID:
            element['id'] = self.stanzaID
        return element



class ErrorStanza(Stanza):

    def parseElement(self, element):
        Stanza.parseElement(self, element)
        self.exception = error.exceptionFromStanza(element)



class Request(Stanza):
    """
    IQ request stanza.

    This is a base class for IQ get or set stanzas, to be used with
    L{wokkel.subprotocols.StreamManager.request}.
    """

    stanzaKind = 'iq'
    stanzaType = 'get'
    timeout = None

    childParsers = {None: 'parseRequest'}

    def __init__(self, recipient=None, sender=None, stanzaType=None):
        Stanza.__init__(self, recipient=recipient, sender=sender)
        if stanzaType is not None:
            self.stanzaType = stanzaType


    def parseRequest(self, element):
        """
        Called with the request's child element for parsing.

        When a request instance is created using L{fromElement}, this method
        is called with the child element of the iq. Override this method for
        parsing the request's payload.
        """


    def toElement(self):
        element = Stanza.toElement(self)

        if not self.stanzaID:
            element.addUniqueId()
            self.stanzaID = element['id']

        return element



class DeferredXmlStreamFactory(BootstrapMixin, protocol.ClientFactory):
    protocol = xmlstream.XmlStream

    def __init__(self, authenticator):
        BootstrapMixin.__init__(self)

        self.authenticator = authenticator

        deferred = defer.Deferred()
        self.deferred = deferred
        self.addBootstrap(xmlstream.STREAM_AUTHD_EVENT, self.deferred.callback)
        self.addBootstrap(xmlstream.INIT_FAILED_EVENT, deferred.errback)


    def buildProtocol(self, addr):
        """
        Create an instance of XmlStream.

        A new authenticator instance will be created and passed to the new
        XmlStream. Registered bootstrap event observers are installed as well.
        """
        xs = self.protocol(self.authenticator)
        xs.factory = self
        self.installBootstraps(xs)
        return xs


    def clientConnectionFailed(self, connector, reason):
        self.deferred.errback(reason)



@deprecated(Version("Wokkel", 0, 8, 0), "unicode.encode('idna')")
def prepareIDNName(name):
    """
    Encode a unicode IDN Domain Name into its ACE equivalent.

    This will encode the domain labels, separated by allowed dot code points,
    to their ASCII Compatible Encoding (ACE) equivalent, using punycode. The
    result is an ASCII byte string of the encoded labels, separated by the
    standard full stop.
    """
    return name.encode('idna')
