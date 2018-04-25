# -*- test-case-name: wokkel.test.test_xmppim -*-
#
# Copyright (c) Ralph Meijer.
# See LICENSE for details.

"""
XMPP IM protocol support.

This module provides generic implementations for the protocols defined in
U{RFC 6121<http://www.xmpp.org/rfcs/rfc6121.html>} (XMPP IM).
"""

from __future__ import division, absolute_import

import warnings

from twisted.internet import defer
from twisted.python.compat import iteritems, itervalues, unicode
from twisted.words.protocols.jabber import error
from twisted.words.protocols.jabber.jid import JID
from twisted.words.xish import domish

from cowrie.twisted_xmpp.generic import ErrorStanza, Stanza, Request
from cowrie.twisted_xmpp.subprotocols import IQHandlerMixin
from cowrie.twisted_xmpp.subprotocols import XMPPHandler

NS_XML = 'http://www.w3.org/XML/1998/namespace'
NS_ROSTER = 'jabber:iq:roster'

XPATH_ROSTER_SET = "/iq[@type='set']/query[@xmlns='%s']" % NS_ROSTER



class Presence(domish.Element):
    def __init__(self, to=None, type=None):
        domish.Element.__init__(self, (None, "presence"))
        if type:
            self["type"] = type

        if to is not None:
            self["to"] = to.full()

class AvailablePresence(Presence):
    def __init__(self, to=None, show=None, statuses=None, priority=0):
        Presence.__init__(self, to, type=None)

        if show in ['away', 'xa', 'chat', 'dnd']:
            self.addElement('show', content=show)

        if statuses is not None:
            for lang, status in iteritems(statuses):
                s = self.addElement('status', content=status)
                if lang:
                    s[(NS_XML, "lang")] = lang

        if priority != 0:
            self.addElement('priority', content=unicode(int(priority)))

class UnavailablePresence(Presence):
    def __init__(self, to=None, statuses=None):
        Presence.__init__(self, to, type='unavailable')

        if statuses is not None:
            for lang, status in iteritems(statuses):
                s = self.addElement('status', content=status)
                if lang:
                    s[(NS_XML, "lang")] = lang

class PresenceClientProtocol(XMPPHandler):

    def connectionInitialized(self):
        self.xmlstream.addObserver('/presence', self._onPresence)

    def _getStatuses(self, presence):
        statuses = {}
        for element in presence.elements():
            if element.name == 'status':
                lang = element.getAttribute((NS_XML, 'lang'))
                text = unicode(element)
                statuses[lang] = text
        return statuses

    def _onPresence(self, presence):
        type = presence.getAttribute("type", "available")
        try:
            handler = getattr(self, '_onPresence%s' % (type.capitalize()))
        except AttributeError:
            return
        else:
            handler(presence)

    def _onPresenceAvailable(self, presence):
        entity = JID(presence["from"])

        show = unicode(presence.show or '')
        if show not in ['away', 'xa', 'chat', 'dnd']:
            show = None

        statuses = self._getStatuses(presence)

        try:
            priority = int(unicode(presence.priority or '')) or 0
        except ValueError:
            priority = 0

        self.availableReceived(entity, show, statuses, priority)

    def _onPresenceUnavailable(self, presence):
        entity = JID(presence["from"])

        statuses = self._getStatuses(presence)

        self.unavailableReceived(entity, statuses)

    def _onPresenceSubscribed(self, presence):
        self.subscribedReceived(JID(presence["from"]))

    def _onPresenceUnsubscribed(self, presence):
        self.unsubscribedReceived(JID(presence["from"]))

    def _onPresenceSubscribe(self, presence):
        self.subscribeReceived(JID(presence["from"]))

    def _onPresenceUnsubscribe(self, presence):
        self.unsubscribeReceived(JID(presence["from"]))


    def availableReceived(self, entity, show=None, statuses=None, priority=0):
        """
        Available presence was received.

        @param entity: entity from which the presence was received.
        @type entity: {JID}
        @param show: detailed presence information. One of C{'away'}, C{'xa'},
                     C{'chat'}, C{'dnd'} or C{None}.
        @type show: C{str} or C{NoneType}
        @param statuses: dictionary of natural language descriptions of the
                         availability status, keyed by the language
                         descriptor. A status without a language
                         specified, is keyed with C{None}.
        @type statuses: C{dict}
        @param priority: priority level of the resource.
        @type priority: C{int}
        """

    def unavailableReceived(self, entity, statuses=None):
        """
        Unavailable presence was received.

        @param entity: entity from which the presence was received.
        @type entity: {JID}
        @param statuses: dictionary of natural language descriptions of the
                         availability status, keyed by the language
                         descriptor. A status without a language
                         specified, is keyed with C{None}.
        @type statuses: C{dict}
        """

    def subscribedReceived(self, entity):
        """
        Subscription approval confirmation was received.

        @param entity: entity from which the confirmation was received.
        @type entity: {JID}
        """

    def unsubscribedReceived(self, entity):
        """
        Unsubscription confirmation was received.

        @param entity: entity from which the confirmation was received.
        @type entity: {JID}
        """

    def subscribeReceived(self, entity):
        """
        Subscription request was received.

        @param entity: entity from which the request was received.
        @type entity: {JID}
        """

    def unsubscribeReceived(self, entity):
        """
        Unsubscription request was received.

        @param entity: entity from which the request was received.
        @type entity: {JID}
        """

    def available(self, entity=None, show=None, statuses=None, priority=0):
        """
        Send available presence.

        @param entity: optional entity to which the presence should be sent.
        @type entity: {JID}
        @param show: optional detailed presence information. One of C{'away'},
                     C{'xa'}, C{'chat'}, C{'dnd'}.
        @type show: C{str}
        @param statuses: dictionary of natural language descriptions of the
                         availability status, keyed by the language
                         descriptor. A status without a language
                         specified, is keyed with C{None}.
        @type statuses: C{dict}
        @param priority: priority level of the resource.
        @type priority: C{int}
        """
        self.send(AvailablePresence(entity, show, statuses, priority))

    def unavailable(self, entity=None, statuses=None):
        """
        Send unavailable presence.

        @param entity: optional entity to which the presence should be sent.
        @type entity: {JID}
        @param statuses: dictionary of natural language descriptions of the
                         availability status, keyed by the language
                         descriptor. A status without a language
                         specified, is keyed with C{None}.
        @type statuses: C{dict}
        """
        self.send(UnavailablePresence(entity, statuses))

    def subscribe(self, entity):
        """
        Send subscription request

        @param entity: entity to subscribe to.
        @type entity: {JID}
        """
        self.send(Presence(to=entity, type='subscribe'))

    def unsubscribe(self, entity):
        """
        Send unsubscription request

        @param entity: entity to unsubscribe from.
        @type entity: {JID}
        """
        self.send(Presence(to=entity, type='unsubscribe'))

    def subscribed(self, entity):
        """
        Send subscription confirmation.

        @param entity: entity that subscribed.
        @type entity: {JID}
        """
        self.send(Presence(to=entity, type='subscribed'))

    def unsubscribed(self, entity):
        """
        Send unsubscription confirmation.

        @param entity: entity that unsubscribed.
        @type entity: {JID}
        """
        self.send(Presence(to=entity, type='unsubscribed'))



class BasePresence(Stanza):
    """
    Stanza of kind presence.
    """
    stanzaKind = 'presence'



class AvailabilityPresence(BasePresence):
    """
    Presence.

    This represents availability presence (as opposed to
    L{SubscriptionPresence}).

    @ivar available: The availability being communicated.
    @type available: C{bool}
    @ivar show: More specific availability. Can be one of C{'chat'}, C{'away'},
                C{'xa'}, C{'dnd'} or C{None}.
    @type show: C{str} or C{NoneType}
    @ivar statuses: Natural language texts to detail the (un)availability.
                    These are represented as a mapping from language code
                    (C{str} or C{None}) to the corresponding text (C{unicode}).
                    If the key is C{None}, the associated text is in the
                    default language.
    @type statuses: C{dict}
    @ivar priority: Priority level for this resource. Must be between -128 and
                    127. Defaults to 0.
    @type priority: C{int}
    """

    childParsers = {(None, 'show'): '_childParser_show',
                     (None, 'status'): '_childParser_status',
                     (None, 'priority'): '_childParser_priority'}

    def __init__(self, recipient=None, sender=None, available=True,
                       show=None, status=None, statuses=None, priority=0):
        BasePresence.__init__(self, recipient=recipient, sender=sender)
        self.available = available
        self.show = show
        self.statuses = statuses or {}
        if status:
            self.statuses[None] = status
        self.priority = priority


    def __get_status(self):
        if None in self.statuses:
            return self.statuses[None]
        elif self.statuses:
            for status in itervalues(self.status):
                return status
        else:
            return None

    status = property(__get_status)


    def _childParser_show(self, element):
        show = unicode(element)
        if show in ('chat', 'away', 'xa', 'dnd'):
            self.show = show


    def _childParser_status(self, element):
        lang = element.getAttribute((NS_XML, 'lang'), None)
        text = unicode(element)
        self.statuses[lang] = text


    def _childParser_priority(self, element):
        try:
            self.priority = int(unicode(element))
        except ValueError:
            pass


    def parseElement(self, element):
        BasePresence.parseElement(self, element)

        if self.stanzaType == 'unavailable':
            self.available = False


    def toElement(self):
        if not self.available:
            self.stanzaType = 'unavailable'

        presence = BasePresence.toElement(self)

        if self.available:
            if self.show in ('chat', 'away', 'xa', 'dnd'):
                presence.addElement('show', content=self.show)
            if self.priority != 0:
                presence.addElement('priority', content=unicode(self.priority))

        for lang, text in iteritems(self.statuses):
            status = presence.addElement('status', content=text)
            if lang:
                status[(NS_XML, 'lang')] = lang

        return presence



class SubscriptionPresence(BasePresence):
    """
    Presence subscription request or response.

    This kind of presence is used to represent requests for presence
    subscription and their replies.

    Based on L{BasePresence} and {Stanza}, it just uses the C{stanzaType}
    attribute to represent the type of subscription presence. This can be
    one of C{'subscribe'}, C{'unsubscribe'}, C{'subscribed'} and
    C{'unsubscribed'}.
    """



class ProbePresence(BasePresence):
    """
    Presence probe request.
    """

    stanzaType = 'probe'



class BasePresenceProtocol(XMPPHandler):
    """
    XMPP Presence base protocol handler.

    This class is the base for protocol handlers that receive presence
    stanzas. Listening to all incoming presence stanzas, it extracts the
    stanza's type and looks up a matching stanza parser and calls the
    associated method. The method's name is the type + C{Received}. E.g.
    C{availableReceived}. See L{PresenceProtocol} for a complete example.

    @cvar presenceTypeParserMap: Maps presence stanza types to their respective
        stanza parser classes (derived from L{Stanza}).
    @type presenceTypeParserMap: C{dict}
    """

    presenceTypeParserMap = {}

    def connectionInitialized(self):
        self.xmlstream.addObserver("/presence", self._onPresence)



    def _onPresence(self, element):
        """
        Called when a presence stanza has been received.
        """
        stanza = Stanza.fromElement(element)

        presenceType = stanza.stanzaType or 'available'

        try:
            parser = self.presenceTypeParserMap[presenceType]
        except KeyError:
            return

        presence = parser.fromElement(element)

        try:
            handler = getattr(self, '%sReceived' % presenceType)
        except AttributeError:
            return
        else:
            handler(presence)



class PresenceProtocol(BasePresenceProtocol):

    presenceTypeParserMap = {
                'error': ErrorStanza,
                'available': AvailabilityPresence,
                'unavailable': AvailabilityPresence,
                'subscribe': SubscriptionPresence,
                'unsubscribe': SubscriptionPresence,
                'subscribed': SubscriptionPresence,
                'unsubscribed': SubscriptionPresence,
                'probe': ProbePresence,
                }


    def errorReceived(self, presence):
        """
        Error presence was received.
        """
        pass


    def availableReceived(self, presence):
        """
        Available presence was received.
        """
        pass


    def unavailableReceived(self, presence):
        """
        Unavailable presence was received.
        """
        pass


    def subscribedReceived(self, presence):
        """
        Subscription approval confirmation was received.
        """
        pass


    def unsubscribedReceived(self, presence):
        """
        Unsubscription confirmation was received.
        """
        pass


    def subscribeReceived(self, presence):
        """
        Subscription request was received.
        """
        pass


    def unsubscribeReceived(self, presence):
        """
        Unsubscription request was received.
        """
        pass


    def probeReceived(self, presence):
        """
        Probe presence was received.
        """
        pass


    def available(self, recipient=None, show=None, statuses=None, priority=0,
                        status=None, sender=None):
        """
        Send available presence.

        @param recipient: Optional Recipient to which the presence should be
            sent.
        @type recipient: {JID}

        @param show: Optional detailed presence information. One of C{'away'},
            C{'xa'}, C{'chat'}, C{'dnd'}.
        @type show: C{str}

        @param statuses: Mapping of natural language descriptions of the
           availability status, keyed by the language descriptor. A status
           without a language specified, is keyed with C{None}.
        @type statuses: C{dict}

        @param priority: priority level of the resource.
        @type priority: C{int}
        """
        presence = AvailabilityPresence(recipient=recipient, sender=sender,
                                        show=show, statuses=statuses,
                                        status=status, priority=priority)
        self.send(presence.toElement())


    def unavailable(self, recipient=None, statuses=None, sender=None):
        """
        Send unavailable presence.

        @param recipient: Optional entity to which the presence should be sent.
        @type recipient: {JID}

        @param statuses: dictionary of natural language descriptions of the
            availability status, keyed by the language descriptor. A status
            without a language specified, is keyed with C{None}.
        @type statuses: C{dict}
        """
        presence = AvailabilityPresence(recipient=recipient, sender=sender,
                                        available=False, statuses=statuses)
        self.send(presence.toElement())


    def subscribe(self, recipient, sender=None):
        """
        Send subscription request

        @param recipient: Entity to subscribe to.
        @type recipient: {JID}
        """
        presence = SubscriptionPresence(recipient=recipient, sender=sender)
        presence.stanzaType = 'subscribe'
        self.send(presence.toElement())


    def unsubscribe(self, recipient, sender=None):
        """
        Send unsubscription request

        @param recipient: Entity to unsubscribe from.
        @type recipient: {JID}
        """
        presence = SubscriptionPresence(recipient=recipient, sender=sender)
        presence.stanzaType = 'unsubscribe'
        self.send(presence.toElement())


    def subscribed(self, recipient, sender=None):
        """
        Send subscription confirmation.

        @param recipient: Entity that subscribed.
        @type recipient: {JID}
        """
        presence = SubscriptionPresence(recipient=recipient, sender=sender)
        presence.stanzaType = 'subscribed'
        self.send(presence.toElement())


    def unsubscribed(self, recipient, sender=None):
        """
        Send unsubscription confirmation.

        @param recipient: Entity that unsubscribed.
        @type recipient: {JID}
        """
        presence = SubscriptionPresence(recipient=recipient, sender=sender)
        presence.stanzaType = 'unsubscribed'
        self.send(presence.toElement())


    def probe(self, recipient, sender=None):
        """
        Send presence probe.

        @param recipient: Entity to be probed.
        @type recipient: {JID}
        """
        presence = ProbePresence(recipient=recipient, sender=sender)
        self.send(presence.toElement())



class RosterItem(object):
    """
    Roster item.

    This represents one contact from an XMPP contact list known as roster.

    @ivar entity: The JID of the contact.
    @type entity: L{JID}
    @ivar name: The associated nickname for this contact.
    @type name: C{unicode}
    @ivar subscriptionTo: Subscription state to contact's presence. If C{True},
                          the roster owner is subscribed to the presence
                          information of the contact.
    @type subscriptionTo: C{bool}
    @ivar subscriptionFrom: Contact's subscription state. If C{True}, the
                            contact is subscribed to the presence information
                            of the roster owner.
    @type subscriptionFrom: C{bool}
    @ivar pendingOut: Whether the subscription request to this contact is
        pending.
    @type pendingOut: C{bool}
    @ivar groups: Set of groups this contact is categorized in. Groups are
                  represented by an opaque identifier of type C{unicode}.
    @type groups: C{set}
    @ivar approved: Signals pre-approved subscription.
    @type approved: C{bool}
    @ivar remove: Signals roster item removal.
    @type remove: C{bool}
    """

    __subscriptionStates = {(False, False): None,
                            (True, False): 'to',
                            (False, True): 'from',
                            (True, True): 'both'}

    def __init__(self, entity, subscriptionTo=False, subscriptionFrom=False,
                       name=u'', groups=None):
        self.entity = entity
        self.subscriptionTo = subscriptionTo
        self.subscriptionFrom = subscriptionFrom
        self.name = name
        self.groups = groups or set()

        self.pendingOut = False
        self.approved = False
        self.remove = False


    def __getJID(self):
        warnings.warn(
            "wokkel.xmppim.RosterItem.jid was deprecated in Wokkel 0.7.1; "
            "please use RosterItem.entity instead.",
            DeprecationWarning)
        return self.entity


    def __setJID(self, value):
        warnings.warn(
            "wokkel.xmppim.RosterItem.jid was deprecated in Wokkel 0.7.1; "
            "please use RosterItem.entity instead.",
            DeprecationWarning)
        self.entity = value


    jid = property(__getJID, __setJID,
                   doc="JID of the contact. "
                       "Deprecated in Wokkel 0.7.1; "
                       "please use C{entity} instead.")


    def __getAsk(self):
        warnings.warn(
            "wokkel.xmppim.RosterItem.ask was deprecated in Wokkel 0.7.1; "
            "please use RosterItem.pendingOut instead.",
            DeprecationWarning)
        return self.pendingOut


    def __setAsk(self, value):
        warnings.warn(
            "wokkel.xmppim.RosterItem.ask was deprecated in Wokkel 0.7.1; "
            "please use RosterItem.pendingOut instead.",
            DeprecationWarning)
        self.pendingOut = value


    ask = property(__getAsk, __setAsk,
                   doc="Pending out subscription. "
                       "Deprecated in Wokkel 0.7.1; "
                       "please use C{pendingOut} instead.")


    def toElement(self, rosterSet=False):
        """
        Render to a DOM representation.

        If C{rosterSet} is set, some attributes, that may not be sent
        as a roster set, will not be rendered.

        @type rosterSet: C{boolean}.
        """
        element = domish.Element((NS_ROSTER, 'item'))
        element['jid'] = self.entity.full()

        if self.remove:
            subscription = 'remove'
        else:
            if self.name:
                element['name'] = self.name

            if self.groups:
                for group in self.groups:
                    element.addElement('group', content=group)

            if rosterSet:
                subscription = None
            else:
                subscription = self.__subscriptionStates[self.subscriptionTo,
                                                         self.subscriptionFrom]

                if self.pendingOut:
                    element['ask'] = u'subscribe'

                if self.approved:
                    element['approved'] = u'true'

        if subscription:
            element['subscription'] = subscription

        return element


    @classmethod
    def fromElement(Class, element):
        entity = JID(element['jid'])
        item = Class(entity)
        subscription = element.getAttribute('subscription')
        if subscription == 'remove':
            item.remove = True
        else:
            item.name = element.getAttribute('name', u'')
            item.subscriptionTo = subscription in ('to', 'both')
            item.subscriptionFrom = subscription in ('from', 'both')
            item.pendingOut = element.getAttribute('ask') == 'subscribe'
            item.approved = element.getAttribute('approved') in ('true', '1')
            for subElement in domish.generateElementsQNamed(element.children,
                                                            'group', NS_ROSTER):
                item.groups.add(unicode(subElement))
        return item



class RosterRequest(Request):
    """
    Roster request.

    @ivar item: Roster item to be set or pushed.
    @type item: L{RosterItem}.

    @ivar version: Roster version identifier for roster pushes and
        retrieving the roster as a delta from a known cached version. This
        should only be set if the recipient is known to support roster
        versioning.
    @type version: C{unicode}

    @ivar rosterSet: If set, this is a roster set request. This flag is used
        to make sure some attributes of the roster item are not rendered by
        L{toElement}.
    @type roster: C{boolean}
    """
    item = None
    version = None
    rosterSet = False

    def parseRequest(self, element):
        self.version = element.getAttribute('ver')

        for child in element.elements(NS_ROSTER, 'item'):
            self.item = RosterItem.fromElement(child)
            break


    def toElement(self):
        element = Request.toElement(self)
        query = element.addElement((NS_ROSTER, 'query'))
        if self.version is not None:
            query['ver'] = self.version
        if self.item:
            query.addChild(self.item.toElement(rosterSet=self.rosterSet))
        return element



class RosterPushIgnored(Exception):
    """
    Raised when this entity doesn't want to accept/trust a roster push.

    To avert presence leaks, a handler can raise L{RosterPushIgnored} when
    not accepting a roster push (directly or via Deferred). This will
    result in a C{'service-unavailable'} error being sent in return.
    """



class Roster(dict):
    """
    In-memory roster container.

    This provides a roster as a mapping from L{JID} to L{RosterItem}. If
    roster versioning is used, the C{version} attribute holds the version
    identifier for this version of the roster.

    @ivar version: Roster version identifier.
    @type version: C{unicode}.
    """

    version = None



class RosterClientProtocol(XMPPHandler, IQHandlerMixin):
    """
    Client side XMPP roster protocol.

    The roster can be retrieved using L{getRoster}. Subsequent changes to the
    roster will be pushed, resulting in calls to L{setReceived} or
    L{removeReceived}. These methods should be overridden to handle the
    roster pushes.

    RFC 6121 specifically allows entities other than a user's server to
    hold a roster for that user. However, how a client should deal with
    that is currently not yet specfied.

    By default roster pushes from other source. I.e. when C{request.sender}
    is set but the sender's bare JID is different from the user's bare JID.
    Set L{allowAnySender} to allow roster pushes from any sender. To
    avert presence leaks, L{RosterPushIgnored} should then be raised for
    pushes from untrusted senders.

    If roster versioning is supported by the server, the roster and
    subsequent pushes are annotated with a version identifier. This can be
    used to cache the roster on the client side. Upon reconnect, the client
    can request the roster with the version identifier of the cached version.
    The server may then choose to only send roster pushes for the changes
    since that version, instead of a complete roster.

    @cvar allowAnySender: Flag to allow roster pushes from any sender.
        C{False} by default.
    @type allowAnySender: C{boolean}
    """

    allowAnySender = False
    iqHandlers = {XPATH_ROSTER_SET: "_onRosterSet"}


    def connectionInitialized(self):
        self.xmlstream.addObserver(XPATH_ROSTER_SET, self.handleRequest)


    def getRoster(self, version=None):
        """
        Retrieve contact list.

        The returned deferred fires with the result of the roster request as
        L{Roster}, a mapping from contact JID to L{RosterItem}.

        If roster versioning is supported, the recipient responds with either
        a the complete roster or with an empty result. In case of complete
        roster, the L{Roster} is annotated with a C{version} attribute that
        holds the version identifier for this version of the roster. This
        identifier should be used for caching.

        If the recipient responds with an empty result, the returned deferred
        fires with C{None}. This indicates that any roster modifications
        since C{version} will be sent as roster pushes.

        Note that the empty result (C{None}) is different from an empty
        roster (L{Roster} with no items).

        @param version: Optional version identifier of the last cashed
            version of the roster. This shall only be set if the recipient is
            known to support roster versioning. If there is no (valid) cached
            version of the roster, but roster versioning is desired,
            C{version} should be set to the empty string (C{u''}).
        @type version: C{unicode}

        @return: Roster as a mapping from L{JID} to L{RosterItem}.
        @rtype: L{twisted.internet.defer.Deferred}
        """

        def processRoster(result):
            if result.query is not None:
                roster = Roster()
                roster.version = result.query.getAttribute('ver')
                for element in result.query.elements(NS_ROSTER, 'item'):
                    item = RosterItem.fromElement(element)
                    roster[item.entity] = item
                return roster
            else:
                return None

        request = RosterRequest(stanzaType='get')
        request.version = version
        d = self.request(request)
        d.addCallback(processRoster)
        return d


    def setItem(self, item):
        """
        Add or modify a roster item.

        Note that RFC 6121 doesn't allow all properties of a roster item to
        be sent when setting a roster item. Only the C{name} and C{groups}
        attributes from C{item} are sent to the server. Presence subscription
        management must be done through L{PresenceProtocol}.

        @param item: The roster item to be set.
        @type item: L{RosterItem}.

        @rtype: L{twisted.internet.defer.Deferred}
        """
        request = RosterRequest(stanzaType='set')
        request.rosterSet = True
        request.item = item
        return self.request(request)


    def removeItem(self, entity):
        """
        Remove an item from the contact list.

        @param entity: The contact to remove the roster item for.
        @type entity: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @rtype: L{twisted.internet.defer.Deferred}
        """
        item = RosterItem(entity)
        item.remove = True
        return self.setItem(item)


    def _onRosterSet(self, iq):
        def trapIgnored(failure):
            failure.trap(RosterPushIgnored)
            raise error.StanzaError('service-unavailable')

        request = RosterRequest.fromElement(iq)

        if (not self.allowAnySender and
                request.sender and
                request.sender.userhostJID() !=
                self.parent.jid.userhostJID()):
            d = defer.fail(RosterPushIgnored())
        elif request.item.remove:
            d = defer.maybeDeferred(self.removeReceived, request)
        else:
            d = defer.maybeDeferred(self.setReceived, request)
        d.addErrback(trapIgnored)
        return d


    def setReceived(self, request):
        """
        Called when a roster push for a new or update item was received.

        @param request: The push request.
        @type request: L{RosterRequest}
        """
        if hasattr(self, 'onRosterSet'):
            warnings.warn(
                "wokkel.xmppim.RosterClientProtocol.onRosterSet "
                "was deprecated in Wokkel 0.7.1; "
                "please use RosterClientProtocol.setReceived instead.",
                DeprecationWarning)
            return defer.maybeDeferred(self.onRosterSet, request.item)


    def removeReceived(self, request):
        """
        Called when a roster push for the removal of an item was received.

        @param request: The push request.
        @type request: L{RosterRequest}
        """
        if hasattr(self, 'onRosterRemove'):
            warnings.warn(
                "wokkel.xmppim.RosterClientProtocol.onRosterRemove "
                "was deprecated in Wokkel 0.7.1; "
                "please use RosterClientProtocol.removeReceived instead.",
                DeprecationWarning)
            return defer.maybeDeferred(self.onRosterRemove,
                                       request.item.entity)



class Message(Stanza):
    """
    A message stanza.
    """

    stanzaKind = 'message'

    childParsers = {
            (None, 'body'): '_childParser_body',
            (None, 'subject'): '_childParser_subject',
            }

    def __init__(self, recipient=None, sender=None, body=None, subject=None):
        Stanza.__init__(self, recipient, sender)
        self.body = body
        self.subject = subject


    def _childParser_body(self, element):
        self.body = unicode(element)


    def _childParser_subject(self, element):
        self.subject = unicode(element)


    def toElement(self):
        element = Stanza.toElement(self)

        if self.body:
            element.addElement('body', content=self.body)
        if self.subject:
            element.addElement('subject', content=self.subject)

        return element



class MessageProtocol(XMPPHandler):
    """
    Generic XMPP subprotocol handler for incoming message stanzas.
    """

    messageTypes = None, 'normal', 'chat', 'headline', 'groupchat'

    def connectionInitialized(self):
        self.xmlstream.addObserver("/message", self._onMessage)

    def _onMessage(self, message):
        if message.handled:
            return

        messageType = message.getAttribute("type")

        if messageType == 'error':
            return

        if messageType not in self.messageTypes:
            message["type"] = 'normal'

        self.onMessage(message)

    def onMessage(self, message):
        """
        Called when a message stanza was received.
        """
