# -*- test-case-name: wokkel.test.test_muc -*-
#
# Copyright (c) Ralph Meijer.
# See LICENSE for details.

"""
XMPP Multi-User Chat protocol.

This protocol is specified in
U{XEP-0045<http://xmpp.org/extensions/xep-0045.html>}.
"""

from __future__ import division, absolute_import

from dateutil.tz import tzutc

from zope.interface import implementer

from twisted.internet import defer
from twisted.python.compat import unicode
from twisted.python.constants import Values, ValueConstant
from twisted.words.protocols.jabber import jid, error, xmlstream
from twisted.words.xish import domish

from cowrie.twisted_xmpp import data_form, generic, iwokkel, xmppim
from cowrie.twisted_xmpp.delay import Delay, DelayMixin
from cowrie.twisted_xmpp.subprotocols import XMPPHandler
from cowrie.twisted_xmpp.iwokkel import IMUCClient

# Multi User Chat namespaces
NS_MUC = 'http://jabber.org/protocol/muc'
NS_MUC_USER = NS_MUC + '#user'
NS_MUC_ADMIN = NS_MUC + '#admin'
NS_MUC_OWNER = NS_MUC + '#owner'
NS_MUC_ROOMINFO = NS_MUC + '#roominfo'
NS_MUC_CONFIG = NS_MUC + '#roomconfig'
NS_MUC_REQUEST = NS_MUC + '#request'
NS_MUC_REGISTER = NS_MUC + '#register'

NS_REGISTER = 'jabber:iq:register'

MESSAGE = '/message'
PRESENCE = '/presence'

GROUPCHAT = MESSAGE +'[@type="groupchat"]'

DEFER_TIMEOUT = 30 # basic timeout is 30 seconds

class STATUS_CODE(Values):
    REALJID_PUBLIC = ValueConstant(100)
    AFFILIATION_CHANGED = ValueConstant(101)
    UNAVAILABLE_SHOWN = ValueConstant(102)
    UNAVAILABLE_NOT_SHOWN = ValueConstant(103)
    CONFIGURATION_CHANGED = ValueConstant(104)
    SELF_PRESENCE = ValueConstant(110)
    LOGGING_ENABLED = ValueConstant(170)
    LOGGING_DISABLED = ValueConstant(171)
    NON_ANONYMOUS = ValueConstant(172)
    SEMI_ANONYMOUS = ValueConstant(173)
    FULLY_ANONYMOUS = ValueConstant(174)
    ROOM_CREATED = ValueConstant(201)
    NICK_ASSIGNED = ValueConstant(210)
    BANNED = ValueConstant(301)
    NEW_NICK = ValueConstant(303)
    KICKED = ValueConstant(307)
    REMOVED_AFFILIATION = ValueConstant(321)
    REMOVED_MEMBERSHIP = ValueConstant(322)
    REMOVED_SHUTDOWN = ValueConstant(332)


@implementer(iwokkel.IMUCStatuses)
class Statuses(set):
    """
    Container of MUC status conditions.

    This is currently implemented as a set of constant values from
    L{STATUS_CODE}. Instances of this class provide L{IMUCStatuses}, that
    defines the supported operations. Even though this class currently derives
    from L{set}, future versions might not. This provides an upgrade path to
    cater for extensible status conditions, as defined in
    U{XEP-0306<http://xmpp.org/extensions/xep-0306.html>}.
    """



class _FormRequest(generic.Request):
    """
    Base class for form exchange requests.
    """
    requestNamespace = None
    formNamespace = None

    def __init__(self, recipient, sender=None, options=None):
        if options is None:
            stanzaType = 'get'
        else:
            stanzaType = 'set'

        generic.Request.__init__(self, recipient, sender, stanzaType)
        self.options = options


    def toElement(self):
        element = generic.Request.toElement(self)

        query = element.addElement((self.requestNamespace, 'query'))
        if self.options is None:
            # This is a request for the configuration form.
            form = None
        elif self.options is False:
            form = data_form.Form(formType='cancel')
        else:
            form = data_form.Form(formType='submit',
                                  formNamespace=self.formNamespace)
            form.makeFields(self.options)

        if form is not None:
            query.addChild(form.toElement())

        return element



class ConfigureRequest(_FormRequest):
    """
    Configure MUC room request.

    http://xmpp.org/extensions/xep-0045.html#roomconfig
    """

    requestNamespace = NS_MUC_OWNER
    formNamespace = NS_MUC_CONFIG



class RegisterRequest(_FormRequest):
    """
    Register request.

    http://xmpp.org/extensions/xep-0045.html#register
    """

    requestNamespace = NS_REGISTER
    formNamespace = NS_MUC_REGISTER



class AdminItem(object):
    """
    Item representing role and/or affiliation for admin request.
    """

    def __init__(self, affiliation=None, role=None, entity=None, nick=None,
                       reason=None):
        self.affiliation = affiliation
        self.role = role
        self.entity = entity
        self.nick = nick
        self.reason = reason


    def toElement(self):
        element = domish.Element((NS_MUC_ADMIN, 'item'))

        if self.entity:
            element['jid'] = self.entity.full()

        if self.nick:
            element['nick'] = self.nick

        if self.affiliation:
            element['affiliation'] = self.affiliation

        if self.role:
            element['role'] = self.role

        if self.reason:
            element.addElement('reason', content=self.reason)

        return element


    @classmethod
    def fromElement(Class, element):
        item = Class()

        if element.hasAttribute('jid'):
            item.entity = jid.JID(element['jid'])

        item.nick = element.getAttribute('nick')
        item.affiliation = element.getAttribute('affiliation')
        item.role = element.getAttribute('role')

        for child in element.elements(NS_MUC_ADMIN, 'reason'):
            item.reason = unicode(child)

        return item



class AdminStanza(generic.Request):
    """
    An admin request or response.
    """

    childParsers = {(NS_MUC_ADMIN, 'query'): '_childParser_query'}

    def toElement(self):
        element = generic.Request.toElement(self)
        element.addElement((NS_MUC_ADMIN, 'query'))

        if self.items:
            for item in self.items:
                element.query.addChild(item.toElement())

        return element


    def _childParser_query(self, element):
        self.items = []
        for child in element.elements(NS_MUC_ADMIN, 'item'):
            self.items.append(AdminItem.fromElement(child))



class DestructionRequest(generic.Request):
    """
    Room destruction request.

    @param reason: Optional reason for the destruction of this room.
    @type reason: L{unicode}.

    @param alternate: Optional room JID of an alternate venue.
    @type alternate: L{JID<twisted.words.protocols.jabber.jid.JID>}

    @param password: Optional password for entering the alternate venue.
    @type password: L{unicode}
    """

    stanzaType = 'set'

    def __init__(self, recipient, sender=None, reason=None, alternate=None,
                       password=None):
        generic.Request.__init__(self, recipient, sender)
        self.reason = reason
        self.alternate = alternate
        self.password = password


    def toElement(self):
        element = generic.Request.toElement(self)
        element.addElement((NS_MUC_OWNER, 'query'))
        element.query.addElement('destroy')

        if self.alternate:
            element.query.destroy['jid'] = self.alternate.full()

            if self.password:
                element.query.destroy.addElement('password',
                                                 content=self.password)

        if self.reason:
            element.query.destroy.addElement('reason', content=self.reason)

        return element



class GroupChat(xmppim.Message, DelayMixin):
    """
    A groupchat message.
    """

    stanzaType = 'groupchat'

    def toElement(self, legacyDelay=False):
        """
        Render into a domish Element.

        @param legacyDelay: If L{True} send the delayed delivery information
        in legacy format.
        """
        element = xmppim.Message.toElement(self)

        if self.delay:
            element.addChild(self.delay.toElement(legacy=legacyDelay))

        return element



class PrivateChat(xmppim.Message):
    """
    A chat message.
    """

    stanzaType = 'chat'



class InviteMessage(xmppim.Message):

    def __init__(self, recipient=None, sender=None, invitee=None, reason=None):
        xmppim.Message.__init__(self, recipient, sender)
        self.invitee = invitee
        self.reason = reason


    def toElement(self):
        element = xmppim.Message.toElement(self)

        child = element.addElement((NS_MUC_USER, 'x'))
        child.addElement('invite')
        child.invite['to'] = self.invitee.full()

        if self.reason:
            child.invite.addElement('reason', content=self.reason)

        return element



class HistoryOptions(object):
    """
    A history configuration object.

    @ivar maxchars: Limit the total number of characters in the history to "X"
        (where the character count is the characters of the complete XML
        stanzas, not only their XML character data).
    @type maxchars: L{int}

    @ivar maxstanzas: Limit the total number of messages in the history to "X".
    @type mazstanzas: L{int}

    @ivar seconds: Send only the messages received in the last "X" seconds.
    @type seconds: L{int}

    @ivar since: Send only the messages received since the datetime specified.
        Note that this must be an offset-aware instance.
    @type since: L{datetime.datetime}
    """
    attributes = ['maxChars', 'maxStanzas', 'seconds', 'since']

    def __init__(self, maxChars=None, maxStanzas=None, seconds=None,
                       since=None):
        self.maxChars = maxChars
        self.maxStanzas = maxStanzas
        self.seconds = seconds
        self.since = since


    def toElement(self):
        """
        Returns a L{domish.Element} representing the history options.
        """
        element = domish.Element((NS_MUC, 'history'))

        for key in self.attributes:
            value = getattr(self, key, None)
            if value is not None:
                if key == 'since':
                    stamp = value.astimezone(tzutc())
                    element[key] = stamp.strftime('%Y-%m-%dT%H:%M:%SZ')
                else:
                    element[key.lower()] = str(value)

        return element



class BasicPresence(xmppim.AvailabilityPresence):
    """
    Availability presence sent from MUC client to service.

    @type history: L{HistoryOptions}
    """
    history = None
    password = None

    def toElement(self):
        element = xmppim.AvailabilityPresence.toElement(self)

        muc = element.addElement((NS_MUC, 'x'))
        if self.password:
            muc.addElement('password', content=self.password)
        if self.history:
            muc.addChild(self.history.toElement())

        return element



class UserPresence(xmppim.AvailabilityPresence):
    """
    Availability presence sent from MUC service to client.

    @ivar affiliation: Affiliation of the entity to the room.
    @type affiliation: L{unicode}

    @ivar role: Role of the entity in the room.
    @type role: L{unicode}

    @ivar entity: The real JID of the entity this presence is from.
    @type entity: L{JID<twisted.words.protocols.jabber.jid.JID>}

    @ivar mucStatuses: Set of one or more status codes from L{STATUS_CODE}.
        See L{Statuses} for usage notes.
    @type mucStatuses: L{Statuses}

    @ivar nick: The nick name of the entity in the room.
    @type nick: L{unicode}
    """

    affiliation = None
    role = None
    entity = None
    nick = None

    mucStatuses = None

    childParsers = {(NS_MUC_USER, 'x'): '_childParser_mucUser'}

    def __init__(self, *args, **kwargs):
        self.mucStatuses = Statuses()
        xmppim.AvailabilityPresence.__init__(self, *args, **kwargs)


    def _childParser_mucUser(self, element):
        """
        Parse the MUC user extension element.
        """
        for child in element.elements():
            if child.uri != NS_MUC_USER:
                continue

            elif child.name == 'status':
                try:
                    value = int(child.getAttribute('code'))
                    statusCode = STATUS_CODE.lookupByValue(value)
                except (TypeError, ValueError):
                    continue

                self.mucStatuses.add(statusCode)

            elif child.name == 'item':
                if child.hasAttribute('jid'):
                    self.entity = jid.JID(child['jid'])

                self.nick = child.getAttribute('nick')
                self.affiliation = child.getAttribute('affiliation')
                self.role = child.getAttribute('role')

                for reason in child.elements(NS_MUC_ADMIN, 'reason'):
                    self.reason = unicode(reason)

            # TODO: destroy



class VoiceRequest(xmppim.Message):
    """
    Voice request message.
    """

    def toElement(self):
        element = xmppim.Message.toElement(self)

        # build data form
        form = data_form.Form('submit', formNamespace=NS_MUC_REQUEST)
        form.addField(data_form.Field(var='muc#role',
                                      value='participant',
                                      label='Requested role'))
        element.addChild(form.toElement())

        return element



class MUCClientProtocol(xmppim.BasePresenceProtocol):
    """
    Multi-User Chat client protocol.
    """

    timeout = None

    presenceTypeParserMap = {
                'error': generic.ErrorStanza,
                'available': UserPresence,
                'unavailable': UserPresence,
                }

    def __init__(self, reactor=None):
        XMPPHandler.__init__(self)

        if reactor:
            self._reactor = reactor
        else:
            from twisted.internet import reactor
            self._reactor = reactor


    def connectionInitialized(self):
        """
        Called when the XML stream has been initialized.

        It initializes several XPath events to handle MUC stanzas that come
        in.
        """
        xmppim.BasePresenceProtocol.connectionInitialized(self)
        self.xmlstream.addObserver(GROUPCHAT, self._onGroupChat)
        self._roomOccupantMap = {}


    def _onGroupChat(self, element):
        """
        A group chat message has been received from a MUC room.

        There are a few event methods that may get called here.
        L{receivedGroupChat}, L{receivedSubject} or L{receivedHistory}.
        """
        message = GroupChat.fromElement(element)
        self.groupChatReceived(message)


    def groupChatReceived(self, message):
        """
        Called when a groupchat message was received.

        This method is called with a parsed representation of a received
        groupchat message and can be overridden for further processing.

        For regular groupchat message, the C{body} attribute contains the
        message body. Conversation history sent by the room upon joining, will
        have the C{delay} attribute set, room subject changes the C{subject}
        attribute. See L{GroupChat} for details.

        @param message: Groupchat message.
        @type message: L{GroupChat}
        """
        pass


    def _sendDeferred(self, stanza):
        """
        Send presence stanza, adding a deferred with a timeout.

        @param stanza: The presence stanza to send over the wire.
        @type stanza: L{generic.Stanza}

        @param timeout: The number of seconds to wait before the deferred is
            timed out.
        @type timeout: L{int}

        The deferred object L{defer.Deferred} is returned.
        """
        def onResponse(element):
            if element.getAttribute('type') == 'error':
                d.errback(error.exceptionFromStanza(element))
            else:
                d.callback(UserPresence.fromElement(element))

        def onTimeout():
            d.errback(xmlstream.TimeoutError("Timeout waiting for response."))

        def cancelTimeout(result):
            if call.active():
                call.cancel()

            return result

        def recordOccupant(presence):
            occupantJID = presence.sender
            roomJID = occupantJID.userhostJID()
            self._roomOccupantMap[roomJID] = occupantJID
            return presence

        call = self._reactor.callLater(DEFER_TIMEOUT, onTimeout)

        d = defer.Deferred()
        d.addBoth(cancelTimeout)
        d.addCallback(recordOccupant)

        query = "/presence[@from='%s' or (@from='%s' and @type='error')]" % (
                stanza.recipient.full(), stanza.recipient.userhost())
        self.xmlstream.addOnetimeObserver(query, onResponse, priority=-1)
        self.xmlstream.send(stanza.toElement())
        return d


    def join(self, roomJID, nick, historyOptions=None, password=None):
        """
        Join a MUC room by sending presence to it.

        @param roomJID: The JID of the room the entity is joining.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The nick name for the entitity joining the room.
        @type nick: L{unicode}

        @param historyOptions: Options for conversation history sent by the
            room upon joining.
        @type historyOptions: L{HistoryOptions}

        @param password: Optional password for the room.
        @type password: L{unicode}

        @return: A deferred that fires when the entity is in the room or an
                 error has occurred.
        """
        occupantJID = jid.JID(tuple=(roomJID.user, roomJID.host, nick))

        presence = BasicPresence(recipient=occupantJID)
        if password:
            presence.password = password
        if historyOptions:
            presence.history = historyOptions

        return self._sendDeferred(presence)


    def nick(self, roomJID, nick):
        """
        Change an entity's nick name in a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#changenick

        @param roomJID: The JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The new nick name within the room.
        @type nick: L{unicode}
        """
        occupantJID = jid.JID(tuple=(roomJID.user, roomJID.host, nick))
        presence = BasicPresence(recipient=occupantJID)
        return self._sendDeferred(presence)


    def status(self, roomJID, show=None, status=None):
        """
        Change user status.

        See: http://xmpp.org/extensions/xep-0045.html#changepres

        @param roomJID: The Room JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param show: The availability of the entity. Common values are xa,
            available, etc
        @type show: L{unicode}

        @param status: The current status of the entity.
        @type status: L{unicode}
        """
        occupantJID = self._roomOccupantMap[roomJID]
        presence = BasicPresence(recipient=occupantJID, show=show,
                                 status=status)
        return self._sendDeferred(presence)


    def leave(self, roomJID):
        """
        Leave a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#exit

        @param roomJID: The JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        occupantJID = self._roomOccupantMap[roomJID]
        presence = xmppim.AvailabilityPresence(recipient=occupantJID,
                                               available=False)

        return self._sendDeferred(presence)


    def groupChat(self, roomJID, body):
        """
        Send a groupchat message.
        """
        message = GroupChat(recipient=roomJID, body=body)
        self.send(message.toElement())


    def chat(self, occupantJID, body):
        """
        Send a private chat message to a user in a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#privatemessage

        @param occupantJID: The Room JID of the other user.
        @type occupantJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        message = PrivateChat(recipient=occupantJID, body=body)
        self.send(message.toElement())


    def subject(self, roomJID, subject):
        """
        Change the subject of a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#subject-mod

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param subject: The subject you want to set.
        @type subject: L{unicode}
        """
        message = GroupChat(roomJID.userhostJID(), subject=subject)
        self.send(message.toElement())


    def invite(self, roomJID, invitee, reason=None):
        """
        Invite a xmpp entity to a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#invite

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param invitee: The entity that is being invited.
        @type invitee: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param reason: The reason for the invite.
        @type reason: L{unicode}
        """
        message = InviteMessage(recipient=roomJID, invitee=invitee,
                                reason=reason)
        self.send(message.toElement())


    def getRegisterForm(self, roomJID):
        """
        Grab the registration form for a MUC room.

        @param room: The room jabber/xmpp entity id for the requested
            registration form.
        @type room: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        def cb(response):
            form = data_form.findForm(response.query, NS_MUC_REGISTER)
            return form

        request = RegisterRequest(recipient=roomJID, options=None)
        d = self.request(request)
        d.addCallback(cb)
        return d


    def register(self, roomJID, options):
        """
        Send a request to register for a room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param options: A mapping of field names to values, or L{None} to
            cancel.
        @type options: L{dict}
        """
        if options is None:
            options = False
        request = RegisterRequest(recipient=roomJID, options=options)
        return self.request(request)


    def voice(self, roomJID):
        """
        Request voice for a moderated room.

        @param roomJID: The room jabber/xmpp entity id.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        message = VoiceRequest(recipient=roomJID)
        self.xmlstream.send(message.toElement())


    def history(self, roomJID, messages):
        """
        Send history to create a MUC based on a one on one chat.

        See: http://xmpp.org/extensions/xep-0045.html#continue

        @param roomJID: The room jabber/xmpp entity id.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param messages: The history to send to the room as an ordered list of
                         message, represented by a dictionary with the keys
                         L{'stanza'}, holding the original stanza a
                         L{domish.Element}, and L{'timestamp'} with the
                         timestamp.
        @type messages: L{list} of L{domish.Element}
        """

        for message in messages:
            stanza = message['stanza']
            stanza['type'] = 'groupchat'

            delay = Delay(stamp=message['timestamp'])

            sender = stanza.getAttribute('from')
            if sender is not None:
                delay.sender = jid.JID(sender)

            stanza.addChild(delay.toElement())

            stanza['to'] = roomJID.userhost()
            if stanza.hasAttribute('from'):
                del stanza['from']

            self.xmlstream.send(stanza)


    def getConfiguration(self, roomJID):
        """
        Grab the configuration from the room.

        This sends an iq request to the room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @return: A deferred that fires with the room's configuration form as
            a L{data_form.Form} or L{None} if there are no configuration
            options available.
        """
        def cb(response):
            form = data_form.findForm(response.query, NS_MUC_CONFIG)
            return form

        request = ConfigureRequest(recipient=roomJID, options=None)
        d = self.request(request)
        d.addCallback(cb)
        return d


    def configure(self, roomJID, options):
        """
        Configure a room.

        @param roomJID: The room to configure.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param options: A mapping of field names to values, or L{None} to
            cancel.
        @type options: L{dict}
        """
        if options is None:
            options = False
        request = ConfigureRequest(recipient=roomJID, options=options)
        return self.request(request)


    def _getAffiliationList(self, roomJID, affiliation):
        """
        Send a request for an affiliation list in a room.
        """
        def cb(response):
            stanza = AdminStanza.fromElement(response)
            return stanza.items

        request = AdminStanza(recipient=roomJID, stanzaType='get')
        request.items = [AdminItem(affiliation=affiliation)]
        d = self.request(request)
        d.addCallback(cb)
        return d


    def _getRoleList(self, roomJID, role):
        """
        Send a request for a role list in a room.
        """
        def cb(response):
            stanza = AdminStanza.fromElement(response)
            return stanza.items

        request = AdminStanza(recipient=roomJID, stanzaType='get')
        request.items = [AdminItem(role=role)]
        d = self.request(request)
        d.addCallback(cb)
        return d


    def getMemberList(self, roomJID):
        """
        Get the member list of a room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._getAffiliationList(roomJID, 'member')


    def getAdminList(self, roomJID):
        """
        Get the admin list of a room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._getAffiliationList(roomJID, 'admin')


    def getBanList(self, roomJID):
        """
        Get an outcast list from a room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._getAffiliationList(roomJID, 'outcast')


    def getOwnerList(self, roomJID):
        """
        Get an owner list from a room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._getAffiliationList(roomJID, 'owner')


    def getModeratorList(self, roomJID):
        """
        Get the moderator list of a room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        d = self._getRoleList(roomJID, 'moderator')
        return d


    def _setAffiliation(self, roomJID, entity, affiliation,
                              reason=None, sender=None):
        """
        Send a request to change an entity's affiliation to a MUC room.
        """
        request = AdminStanza(recipient=roomJID, sender=sender,
                               stanzaType='set')
        item = AdminItem(entity=entity, affiliation=affiliation, reason=reason)
        request.items = [item]
        return self.request(request)


    def _setRole(self, roomJID, nick, role,
                       reason=None, sender=None):
        """
        Send a request to change an occupant's role in a MUC room.
        """
        request = AdminStanza(recipient=roomJID, sender=sender,
                               stanzaType='set')
        item = AdminItem(nick=nick, role=role, reason=reason)
        request.items = [item]
        return self.request(request)


    def modifyAffiliationList(self, roomJID, entities, affiliation,
                                    sender=None):
        """
        Modify an affiliation list.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param entities: The list of entities to change for a room.
        @type entities: L{list} of
            L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param affiliation: The affilation to the entities will acquire.
        @type affiliation: L{unicode}

        @param sender: The entity sending the request.
        @type sender: L{JID<twisted.words.protocols.jabber.jid.JID>}

        """
        request = AdminStanza(recipient=roomJID, sender=sender,
                               stanzaType='set')
        request.items = [AdminItem(entity=entity, affiliation=affiliation)
                         for entity in entities]

        return self.request(request)


    def grantVoice(self, roomJID, nick, reason=None, sender=None):
        """
        Grant voice to an entity.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The nick name for the user in this room.
        @type nick: L{unicode}

        @param reason: The reason for granting voice to the entity.
        @type reason: L{unicode}

        @param sender: The entity sending the request.
        @type sender: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._setRole(roomJID, nick=nick,
                             role='participant',
                             reason=reason, sender=sender)


    def revokeVoice(self, roomJID, nick, reason=None, sender=None):
        """
        Revoke voice from a participant.

        This will disallow the entity to send messages to a moderated room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The nick name for the user in this room.
        @type nick: L{unicode}

        @param reason: The reason for revoking voice from the entity.
        @type reason: L{unicode}

        @param sender: The entity sending the request.
        @type sender: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._setRole(roomJID, nick=nick, role='visitor',
                             reason=reason, sender=sender)


    def grantModerator(self, roomJID, nick, reason=None, sender=None):
        """
        Grant moderator privileges to a MUC room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The nick name for the user in this room.
        @type nick: L{unicode}

        @param reason: The reason for granting moderation to the entity.
        @type reason: L{unicode}

        @param sender: The entity sending the request.
        @type sender: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._setRole(roomJID, nick=nick, role='moderator',
                             reason=reason, sender=sender)


    def ban(self, roomJID, entity, reason=None, sender=None):
        """
        Ban a user from a MUC room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param entity: The bare JID of the entity to be banned.
        @type entity: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param reason: The reason for banning the entity.
        @type reason: L{unicode}

        @param sender: The entity sending the request.
        @type sender: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._setAffiliation(roomJID, entity, 'outcast',
                                    reason=reason, sender=sender)


    def kick(self, roomJID, nick, reason=None, sender=None):
        """
        Kick a user from a MUC room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The occupant to be banned.
        @type nick: L{unicode}

        @param reason: The reason given for the kick.
        @type reason: L{unicode}

        @param sender: The entity sending the request.
        @type sender: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._setRole(roomJID, nick, 'none',
                             reason=reason, sender=sender)


    def destroy(self, roomJID, reason=None, alternate=None, password=None):
        """
        Destroy a room.

        @param roomJID: The JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param reason: The reason for the destruction of the room.
        @type reason: L{unicode}

        @param alternate: The JID of the room suggested as an alternate venue.
        @type alternate: L{JID<twisted.words.protocols.jabber.jid.JID>}

        """
        request = DestructionRequest(recipient=roomJID, reason=reason,
                                     alternate=alternate, password=password)

        return self.request(request)



class User(object):
    """
    A user/entity in a multi-user chat room.
    """

    def __init__(self, nick, entity=None):
        self.nick = nick
        self.entity = entity
        self.affiliation = 'none'
        self.role = 'none'

        self.status = None
        self.show = None



class Room(object):
    """
    A Multi User Chat Room.

    An in memory object representing a MUC room from the perspective of
    a client.

    @ivar roomJID: The Room JID of the MUC room.
    @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

    @ivar nick: The nick name for the client in this room.
    @type nick: L{unicode}

    @ivar occupantJID: The JID of the occupant in the room. Generated from
        roomJID and nick.
    @type occupantJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

    @ivar locked: Flag signalling a locked room. A locked room first needs
        to be configured before it can be used. See
        L{MUCClientProtocol.getConfiguration} and
        L{MUCClientProtocol.configure}.
    @type locked: L{bool}
    """

    locked = False

    def __init__(self, roomJID, nick):
        """
        Initialize the room.
        """
        self.roomJID = roomJID
        self.setNick(nick)
        self.roster = {}


    def setNick(self, nick):
        self.occupantJID = jid.internJID(u"%s/%s" % (self.roomJID, nick))
        self.nick = nick


    def addUser(self, user):
        """
        Add a user to the room roster.

        @param user: The user object that is being added to the room.
        @type user: L{User}
        """
        self.roster[user.nick] = user


    def inRoster(self, user):
        """
        Check if a user is in the MUC room.

        @param user: The user object to check.
        @type user: L{User}
        """

        return user.nick in self.roster


    def getUser(self, nick):
        """
        Get a user from the room's roster.

        @param nick: The nick for the user in the MUC room.
        @type nick: L{unicode}
        """
        return self.roster.get(nick)


    def removeUser(self, user):
        """
        Remove a user from the MUC room's roster.

        @param user: The user object to check.
        @type user: L{User}
        """
        if self.inRoster(user):
            del self.roster[user.nick]



@implementer(IMUCClient)
class MUCClient(MUCClientProtocol):
    """
    Multi-User Chat client protocol.

    This is a subclass of L{XMPPHandler} and implements L{IMUCClient}.

    @ivar _rooms: Collection of occupied rooms, keyed by the bare JID of the
                  room. Note that a particular entity can only join a room once
                  at a time.
    @type _rooms: L{dict}
    """

    def __init__(self, reactor=None):
        MUCClientProtocol.__init__(self, reactor)

        self._rooms = {}


    def _addRoom(self, room):
        """
        Add a room to the room collection.

        Rooms are stored by the JID of the room itself. I.e. it uses the Room
        ID and service parts of the Room JID.

        @note: An entity can only join a particular room once.
        """
        roomJID = room.occupantJID.userhostJID()
        self._rooms[roomJID] = room


    def _getRoom(self, roomJID):
        """
        Grab a room from the room collection.

        This uses the Room ID and service parts of the given JID to look up
        the L{Room} instance associated with it.

        @type occupantJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        return self._rooms.get(roomJID)


    def _removeRoom(self, roomJID):
        """
        Delete a room from the room collection.
        """
        if roomJID in self._rooms:
            del self._rooms[roomJID]


    def _getRoomUser(self, stanza):
        """
        Lookup the room and user associated with the stanza's sender.
        """
        occupantJID = stanza.sender

        if not occupantJID:
            return None, None

        # when a user leaves a room we need to update it
        room = self._getRoom(occupantJID.userhostJID())
        if room is None:
            # not in the room yet
            return None, None

        # Check if user is in roster
        nick = occupantJID.resource
        user = room.getUser(nick)

        return room, user


    def unavailableReceived(self, presence):
        """
        Unavailable presence was received.

        If this was received from a MUC room occupant JID, that occupant has
        left the room.
        """

        room, user = self._getRoomUser(presence)

        if room is None or user is None:
            return

        room.removeUser(user)
        self.userLeftRoom(room, user)


    def availableReceived(self, presence):
        """
        Available presence was received.
        """

        room, user = self._getRoomUser(presence)

        if room is None:
            return

        if user is None:
            nick = presence.sender.resource
            user = User(nick, presence.entity)

        # Update user data
        user.role = presence.role
        user.affiliation = presence.affiliation
        user.status = presence.status
        user.show = presence.show

        if room.inRoster(user):
            self.userUpdatedStatus(room, user, presence.show, presence.status)
        else:
            room.addUser(user)
            self.userJoinedRoom(room, user)


    def groupChatReceived(self, message):
        """
        A group chat message has been received from a MUC room.

        There are a few event methods that may get called here.
        L{receivedGroupChat}, L{receivedSubject} or L{receivedHistory}.
        """
        room, user = self._getRoomUser(message)

        if room is None:
            return

        if message.subject:
            self.receivedSubject(room, user, message.subject)
        elif message.delay is None:
            self.receivedGroupChat(room, user, message)
        else:
            self.receivedHistory(room, user, message)


    def userJoinedRoom(self, room, user):
        """
        User has joined a MUC room.

        This method will need to be modified inorder for clients to
        do something when this event occurs.

        @param room: The room the user has joined.
        @type room: L{Room}

        @param user: The user that joined the MUC room.
        @type user: L{User}
        """
        pass


    def userLeftRoom(self, room, user):
        """
        User has left a room.

        This method will need to be modified inorder for clients to
        do something when this event occurs.

        @param room: The room the user has joined.
        @type room: L{Room}

        @param user: The user that left the MUC room.
        @type user: L{User}
        """
        pass


    def userUpdatedStatus(self, room, user, show, status):
        """
        User Presence has been received.

        This method will need to be modified inorder for clients to
        do something when this event occurs.
        """
        pass


    def receivedSubject(self, room, user, subject):
        """
        A (new) room subject has been received.

        This method will need to be modified inorder for clients to
        do something when this event occurs.
        """
        pass


    def receivedGroupChat(self, room, user, message):
        """
        A groupchat message was received.

        @param room: The room the message was received from.
        @type room: L{Room}

        @param user: The user that sent the message, or L{None} if it was a
            message from the room itself.
        @type user: L{User}

        @param message: The message.
        @type message: L{GroupChat}
        """
        pass


    def receivedHistory(self, room, user, message):
        """
        A groupchat message from the room's discussion history was received.

        This is identical to L{receivedGroupChat}, with the delayed delivery
        information (timestamp and original sender) in C{message.delay}. For
        anonymous rooms, C{message.delay.sender} is the room's address.

        @param room: The room the message was received from.
        @type room: L{Room}

        @param user: The user that sent the message, or L{None} if it was a
            message from the room itself.
        @type user: L{User}

        @param message: The message.
        @type message: L{GroupChat}
        """
        pass


    def join(self, roomJID, nick, historyOptions=None,
                   password=None):
        """
        Join a MUC room by sending presence to it.

        @param roomJID: The JID of the room the entity is joining.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The nick name for the entitity joining the room.
        @type nick: L{unicode}

        @param historyOptions: Options for conversation history sent by the
            room upon joining.
        @type historyOptions: L{HistoryOptions}

        @param password: Optional password for the room.
        @type password: L{unicode}

        @return: A deferred that fires with the room when the entity is in the
            room, or with a failure if an error has occurred.
        """
        def cb(presence):
            """
            We have presence that says we joined a room.
            """
            if STATUS_CODE.ROOM_CREATED in presence.mucStatuses:
                room.locked = True

            return room

        def eb(failure):
            self._removeRoom(roomJID)
            return failure

        room = Room(roomJID, nick)
        self._addRoom(room)

        d = MUCClientProtocol.join(self, roomJID, nick, historyOptions,
                                         password)
        d.addCallbacks(cb, eb)
        return d


    def nick(self, roomJID, nick):
        """
        Change an entity's nick name in a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#changenick

        @param roomJID: The JID of the room, i.e. without a resource.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The new nick name within the room.
        @type nick: L{unicode}
        """
        def cb(presence):
            # Presence confirmation, change the nickname.
            room.setNick(nick)
            return room

        room = self._getRoom(roomJID)

        d = MUCClientProtocol.nick(self, roomJID, nick)
        d.addCallback(cb)
        return d


    def leave(self, roomJID):
        """
        Leave a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#exit

        @param roomJID: The Room JID of the room to leave.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """
        def cb(presence):
            self._removeRoom(roomJID)

        d = MUCClientProtocol.leave(self, roomJID)
        d.addCallback(cb)
        return d


    def status(self, roomJID, show=None, status=None):
        """
        Change user status.

        See: http://xmpp.org/extensions/xep-0045.html#changepres

        @param roomJID: The Room JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param show: The availability of the entity. Common values are xa,
            available, etc
        @type show: L{unicode}

        @param status: The current status of the entity.
        @type status: L{unicode}
        """
        room = self._getRoom(roomJID)
        d = MUCClientProtocol.status(self, roomJID, show, status)
        d.addCallback(lambda _: room)
        return d


    def destroy(self, roomJID, reason=None, alternate=None, password=None):
        """
        Destroy a room.

        @param roomJID: The JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param reason: The reason for the destruction of the room.
        @type reason: L{unicode}

        @param alternate: The JID of the room suggested as an alternate venue.
        @type alternate: L{JID<twisted.words.protocols.jabber.jid.JID>}

        """
        def destroyed(iq):
            self._removeRoom(roomJID)

        d = MUCClientProtocol.destroy(self, roomJID, reason, alternate)
        d.addCallback(destroyed)
        return d
