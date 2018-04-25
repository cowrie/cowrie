# -*- test-case-name: wokkel.test.test_subprotocols -*-
#
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
XMPP subprotocol support.
"""

from __future__ import division, absolute_import

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet.error import ConnectionDone
from twisted.python import failure, log
from twisted.python.compat import iteritems, itervalues
from twisted.python.deprecate import deprecatedModuleAttribute
from twisted.python.versions import Version
from twisted.words.protocols.jabber import error, ijabber, xmlstream
from twisted.words.protocols.jabber.xmlstream import toResponse
from twisted.words.protocols.jabber.xmlstream import XMPPHandlerCollection
from twisted.words.xish import xpath
from twisted.words.xish.domish import IElement

deprecatedModuleAttribute(
        Version("Wokkel", 0, 7, 0),
        "Use twisted.words.protocols.jabber.xmlstream.XMPPHandlerCollection "
                "instead.",
        __name__,
        "XMPPHandlerCollection")

@implementer(ijabber.IXMPPHandler)
class XMPPHandler(object):
    """
    XMPP protocol handler.

    Classes derived from this class implement (part of) one or more XMPP
    extension protocols, and are referred to as a subprotocol implementation.
    """

    def __init__(self):
        self.parent = None
        self.xmlstream = None


    def setHandlerParent(self, parent):
        self.parent = parent
        self.parent.addHandler(self)


    def disownHandlerParent(self, parent):
        self.parent.removeHandler(self)
        self.parent = None


    def makeConnection(self, xs):
        self.xmlstream = xs
        self.connectionMade()


    def connectionMade(self):
        """
        Called after a connection has been established.

        Can be overridden to perform work before stream initialization.
        """


    def connectionInitialized(self):
        """
        The XML stream has been initialized.

        Can be overridden to perform work after stream initialization, e.g. to
        set up observers and start exchanging XML stanzas.
        """


    def connectionLost(self, reason):
        """
        The XML stream has been closed.

        This method can be extended to inspect the C{reason} argument and
        act on it.
        """
        self.xmlstream = None


    def send(self, obj):
        """
        Send data over the managed XML stream.

        @note: The stream manager maintains a queue for data sent using this
               method when there is no current initialized XML stream. This
               data is then sent as soon as a new stream has been established
               and initialized. Subsequently, L{connectionInitialized} will be
               called again. If this queueing is not desired, use C{send} on
               C{self.xmlstream}.

        @param obj: data to be sent over the XML stream. This is usually an
                    object providing L{domish.IElement}, or serialized XML. See
                    L{xmlstream.XmlStream} for details.
        """
        self.parent.send(obj)


    def request(self, request):
        """
        Send an IQ request and track the response.

        This passes the request to the parent for sending and response
        tracking.

        @see: L{StreamManager.request}.
        """
        return self.parent.request(request)



class StreamManager(XMPPHandlerCollection):
    """
    Business logic representing a managed XMPP connection.

    This maintains a single XMPP connection and provides facilities for packet
    routing and transmission. Business logic modules are objects providing
    L{IXMPPHandler} (like subclasses of L{XMPPHandler}), and added
    using L{addHandler}.

    @ivar xmlstream: currently managed XML stream
    @type xmlstream: L{XmlStream}
    @ivar logTraffic: if true, log all traffic.
    @type logTraffic: C{bool}
    @ivar _initialized: Whether the stream represented by L{xmlstream} has
                        been initialized. This is used when caching outgoing
                        stanzas.
    @type _initialized: C{bool}
    @ivar _packetQueue: internal buffer of unsent data. See L{send} for details.
    @type _packetQueue: L{list}
    @ivar timeout: Default IQ request timeout in seconds.
    @type timeout: C{int}
    @ivar _reactor: A provider of L{IReactorTime} to track timeouts.
    """
    timeout = None
    _reactor = None

    logTraffic = False

    def __init__(self, factory, reactor=None):
        """
        Construct a stream manager.

        @param factory: The stream factory to connect with.
        @param reactor: A provider of L{IReactorTime} to track timeouts.
            If not provided, the global reactor will be used.
        """
        XMPPHandlerCollection.__init__(self)
        self.xmlstream = None
        self._packetQueue = []
        self._initialized = False

        factory.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT, self._connected)
        factory.addBootstrap(xmlstream.STREAM_AUTHD_EVENT, self._authd)
        factory.addBootstrap(xmlstream.INIT_FAILED_EVENT,
                             self.initializationFailed)
        factory.addBootstrap(xmlstream.STREAM_END_EVENT, self._disconnected)
        self.factory = factory

        if reactor is None:
            from twisted.internet import reactor
        self._reactor = reactor

        # Set up IQ response tracking
        self._iqDeferreds = {}


    def addHandler(self, handler):
        """
        Add protocol handler.

        When an XML stream has already been established, the handler's
        C{connectionInitialized} will be called to get it up to speed.
        """
        XMPPHandlerCollection.addHandler(self, handler)

        # get protocol handler up to speed when a connection has already
        # been established
        if self.xmlstream:
            handler.makeConnection(self.xmlstream)
        if self._initialized:
            handler.connectionInitialized()


    def _connected(self, xs):
        """
        Called when the transport connection has been established.

        Here we optionally set up traffic logging (depending on L{logTraffic})
        and call each handler's C{makeConnection} method with the L{XmlStream}
        instance.
        """
        def logDataIn(buf):
            log.msg("RECV: %r" % buf)

        def logDataOut(buf):
            log.msg("SEND: %r" % buf)

        if self.logTraffic:
            xs.rawDataInFn = logDataIn
            xs.rawDataOutFn = logDataOut

        self.xmlstream = xs

        for e in list(self):
            e.makeConnection(xs)


    def _authd(self, xs):
        """
        Called when the stream has been initialized.

        Send out cached stanzas and call each handler's
        C{connectionInitialized} method.
        """

        xs.addObserver('/iq[@type="result"]', self._onIQResponse)
        xs.addObserver('/iq[@type="error"]', self._onIQResponse)

        # Flush all pending packets
        for p in self._packetQueue:
            xs.send(p)
        self._packetQueue = []
        self._initialized = True

        # Notify all child services which implement
        # the IService interface
        for e in list(self):
            e.connectionInitialized()


    def initializationFailed(self, reason):
        """
        Called when stream initialization has failed.

        Stream initialization has halted, with the reason indicated by
        C{reason}. It may be retried by calling the authenticator's
        C{initializeStream}. See the respective authenticators for details.

        @param reason: A failure instance indicating why stream initialization
                       failed.
        @type reason: L{failure.Failure}
        """


    def _disconnected(self, reason):
        """
        Called when the stream has been closed.

        From this point on, the manager doesn't interact with the
        L{XmlStream} anymore and notifies each handler that the connection
        was lost by calling its C{connectionLost} method.
        """
        self.xmlstream = None
        self._initialized = False

        # Twisted versions before 11.0 passed an XmlStream here.
        if not hasattr(reason, 'trap'):
            reason = failure.Failure(ConnectionDone())

        # Notify all child services which implement
        # the IService interface
        for e in list(self):
            e.connectionLost(reason)

        # This errbacks all deferreds of iq's for which no response has
        # been received with a L{ConnectionLost} failure. Otherwise, the
        # deferreds will never be fired.
        iqDeferreds = self._iqDeferreds
        self._iqDeferreds = {}
        for d in itervalues(iqDeferreds):
            d.errback(reason)


    def _onIQResponse(self, iq):
        """
        Handle iq response by firing associated deferred.
        """
        try:
            d = self._iqDeferreds[iq["id"]]
        except KeyError:
            return

        del self._iqDeferreds[iq["id"]]
        iq.handled = True
        if iq['type'] == 'error':
            d.errback(error.exceptionFromStanza(iq))
        else:
            d.callback(iq)


    def send(self, obj):
        """
        Send data over the XML stream.

        When there is no established XML stream, the data is queued and sent
        out when a new XML stream has been established and initialized.

        @param obj: data to be sent over the XML stream. See
                    L{xmlstream.XmlStream.send} for details.
        """
        if self._initialized:
            self.xmlstream.send(obj)
        else:
            self._packetQueue.append(obj)


    def request(self, request):
        """
        Send an IQ request and track the response.

        A request is an IQ L{generic.Stanza} of type C{'get'} or C{'set'}. It
        will have its C{toElement} called to render to a
        L{Element<twisted.words.xish.domish.Element>} which is then sent out
        over the current stream. If there is no such stream (yet), it is queued
        and sent whenever a connection is established and initialized, just
        like L{send}.

        If the request doesn't have an identifier, it will be assigned a fresh
        one, so the response can be tracked.

        The deferred that is returned will fire with the
        L{Element<twisted.words.xish.domish.Element>} representation of the
        response if it is a result iq. If the response is an error iq, a
        corresponding L{error.StanzaError} will be errbacked.

        If the connection is closed before a response was received, the deferred
        will be errbacked with the reason failure.

        A request may also have a timeout, either by setting a default timeout
        in L{StreamManager}'s C{timeout} attribute or on the C{timeout}
        attribute of the request.

        @param request: The IQ request.
        @type request: L{generic.Request}
        """
        if (request.stanzaKind != 'iq' or
            request.stanzaType not in ('get', 'set')):
            return defer.fail(ValueError("Not a request"))

        element = request.toElement()

        # Make sure we have a trackable id on the stanza
        if not request.stanzaID:
            element.addUniqueId()
            request.stanzaID = element['id']

        # Set up iq response tracking
        d = defer.Deferred()
        self._iqDeferreds[element['id']] = d

        timeout = getattr(request, 'timeout', self.timeout)

        if timeout is not None:
            def onTimeout():
                del self._iqDeferreds[element['id']]
                d.errback(xmlstream.TimeoutError("IQ timed out"))

            call = self._reactor.callLater(timeout, onTimeout)

            def cancelTimeout(result):
                if call.active():
                    call.cancel()

                return result

            d.addBoth(cancelTimeout)
        self.send(element)
        return d



class IQHandlerMixin(object):
    """
    XMPP subprotocol mixin for handle incoming IQ stanzas.

    This matches up the iq with XPath queries to call methods on itself,
    wrapping the call so that exceptions result in proper error responses,
    or, when succesful will reply with a response with optional payload.

    Derivatives of this class must provide an
    L{XmlStream<twisted.words.protocols.jabber.xmlstream.XmlStream>} instance
    in its C{xmlstream} attribute.

    The optional payload is taken from the result of the handler and is
    expected to be a child or a list of childs.

    If an exception is raised, or the deferred has its errback called,
    the exception is checked for being a L{error.StanzaError}. If so,
    an error response is sent. Any other exception will cause a error
    response of C{internal-server-error} to be sent.

    A typical way to use this mixin, is to set up L{xpath} observers on the
    C{xmlstream} to call handleRequest, for example in an overridden
    L{XMPPHandler.connectionMade}. It is likely a good idea to only listen for
    incoming iq get and/org iq set requests, and not for any iq, to prevent
    hijacking incoming responses to outgoing iq requests. An example:

        >>> QUERY_ROSTER = "/query[@xmlns='jabber:iq:roster']"
        >>> class MyHandler(XMPPHandler, IQHandlerMixin):
        ...    iqHandlers = {"/iq[@type='get']" + QUERY_ROSTER: 'onRosterGet',
        ...                  "/iq[@type='set']" + QUERY_ROSTER: 'onRosterSet'}
        ...    def connectionMade(self):
        ...        self.xmlstream.addObserver(
        ...          "/iq[@type='get' or @type='set']" + QUERY_ROSTER,
        ...          self.handleRequest)
        ...    def onRosterGet(self, iq):
        ...        pass
        ...    def onRosterSet(self, iq):
        ...        pass

    @cvar iqHandlers: Mapping from XPath queries (as a string) to the method
                      name that will handle requests that match the query.
    @type iqHandlers: C{dict}
    """

    iqHandlers = None

    def handleRequest(self, iq):
        """
        Find a handler and wrap the call for sending a response stanza.
        """
        def toResult(result, iq):
            response = toResponse(iq, 'result')

            if result:
                if IElement.providedBy(result):
                    response.addChild(result)
                else:
                    for element in result:
                        response.addChild(element)

            return response

        def checkNotImplemented(failure):
            failure.trap(NotImplementedError)
            raise error.StanzaError('feature-not-implemented')

        def fromStanzaError(failure, iq):
            failure.trap(error.StanzaError)
            return failure.value.toResponse(iq)

        def fromOtherError(failure, iq):
            log.msg("Unhandled error in iq handler:", isError=True)
            log.err(failure)
            return error.StanzaError('internal-server-error').toResponse(iq)

        handler = None
        for queryString, method in iteritems(self.iqHandlers):
            if xpath.internQuery(queryString).matches(iq):
                handler = getattr(self, method)

        if handler:
            d = defer.maybeDeferred(handler, iq)
        else:
            d = defer.fail(NotImplementedError())

        d.addCallback(toResult, iq)
        d.addErrback(checkNotImplemented)
        d.addErrback(fromStanzaError, iq)
        d.addErrback(fromOtherError, iq)

        d.addCallback(self.send)

        iq.handled = True



__all__ = ['XMPPHandler', 'XMPPHandlerCollection', 'StreamManager',
           'IQHandlerMixin']
