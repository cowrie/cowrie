# -*- test-case-name: wokkel.test.test_iwokkel -*-
#
# Copyright (c) Ralph Meijer.
# See LICENSE for details.

"""
Wokkel interfaces.
"""

from __future__ import division, absolute_import

from zope.interface import Interface
from twisted.python.deprecate import deprecatedModuleAttribute
from twisted.python.versions import Version
from twisted.words.protocols.jabber.ijabber import IXMPPHandler
from twisted.words.protocols.jabber.ijabber import IXMPPHandlerCollection

deprecatedModuleAttribute(
        Version("Wokkel", 0, 7, 0),
        "Use twisted.words.protocols.jabber.ijabber.IXMPPHandler instead.",
        __name__,
        "IXMPPHandler")

deprecatedModuleAttribute(
        Version("Wokkel", 0, 7, 0),
        "Use twisted.words.protocols.jabber.ijabber.IXMPPHandlerCollection "
                "instead.",
        __name__,
        "IXMPPHandlerCollection")


class IDisco(Interface):
    """
    Interface for XMPP service discovery.
    """

    def getDiscoInfo(requestor, target, nodeIdentifier=''):
        """
        Get identity and features from this entity, node.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param target: The target entity to which the request is made.
        @type target: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The optional identifier of the node at this
            entity to retrieve the identify and features of.  The default is
            C{''}, meaning the root node.
        @type nodeIdentifier: C{unicode}
        """

    def getDiscoItems(requestor, target, nodeIdentifier=''):
        """
        Get contained items for this entity, node.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param target: The target entity to which the request is made.
        @type target: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The optional identifier of the node at this
                               entity to retrieve the identify and features of.
                               The default is C{''}, meaning the root node.
        @type nodeIdentifier: C{unicode}
        """



class IPubSubClient(Interface):

    def itemsReceived(event):
        """
        Called when an items notification has been received for a node.

        An item can be an element named C{item} or C{retract}. Respectively,
        they signal an item being published or retracted, optionally
        accompanied with an item identifier in the C{id} attribute.

        @param event: The items event.
        @type event: L{ItemsEvent<wokkel.pubsub.ItemsEvent>}
        """


    def deleteReceived(event):
        """
        Called when a deletion notification has been received for a node.

        @param event: The items event.
        @type event: L{ItemsEvent<wokkel.pubsub.DeleteEvent>}
        """


    def purgeReceived(event):
        """
        Called when a purge notification has been received for a node.

        Upon receiving this notification all items associated should be
        considered retracted.

        @param event: The items event.
        @type event: L{ItemsEvent<wokkel.pubsub.PurgeEvent>}
        """

    def createNode(service, nodeIdentifier=None):
        """
        Create a new publish subscribe node.

        @param service: The publish-subscribe service entity.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: Optional suggestion for the new node's
                               identifier. If omitted, the creation of an
                               instant node will be attempted.
        @type nodeIdentifier: C{unicode}
        @return: a deferred that fires with the identifier of the newly created
                 node. Note that this can differ from the suggested identifier
                 if the publish subscribe service chooses to modify or ignore
                 the suggested identifier.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def deleteNode(service, nodeIdentifier):
        """
        Delete a node.

        @param service: The publish-subscribe service entity.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: Identifier of the node to be deleted.
        @type nodeIdentifier: C{unicode}
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def subscribe(service, nodeIdentifier, subscriber):
        """
        Subscribe to a node with a given JID.

        @param service: The publish-subscribe service entity.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: Identifier of the node to subscribe to.
        @type nodeIdentifier: C{unicode}
        @param subscriber: JID to subscribe to the node.
        @type subscriber: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def unsubscribe(service, nodeIdentifier, subscriber):
        """
        Unsubscribe from a node with a given JID.

        @param service: The publish-subscribe service entity.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: Identifier of the node to unsubscribe from.
        @type nodeIdentifier: C{unicode}
        @param subscriber: JID to unsubscribe from the node.
        @type subscriber: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def publish(service, nodeIdentifier, items=[]):
        """
        Publish to a node.

        Node that the C{items} parameter is optional, because so-called
        transient, notification-only nodes do not use items and publish
        actions only signify a change in some resource.

        @param service: The publish-subscribe service entity.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: Identifier of the node to publish to.
        @type nodeIdentifier: C{unicode}
        @param items: List of item elements.
        @type items: C{list} of L{Item}
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """



class IPubSubService(Interface):
    """
    Interface for an XMPP Publish Subscribe Service.

    All methods that are called as the result of an XMPP request are to
    return a deferred that fires when the requested action has been performed.
    Alternatively, exceptions maybe raised directly or by calling C{errback}
    on the returned deferred.
    """

    def notifyPublish(service, nodeIdentifier, notifications):
        """
        Send out notifications for a publish event.

        @param service: The entity the notifications will originate from.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node that was published
            to.
        @type nodeIdentifier: C{unicode}
        @param notifications: The notifications as tuples of subscriber, the
            list of subscriptions and the list of items to be notified.
        @type notifications: C{list} of
            (L{JID<twisted.words.protocols.jabber.jid.JID>}, C{list} of
            L{Subscription<wokkel.pubsub.Subscription>}, C{list} of
            L{Element<twisted.words.xish.domish.Element>})
        """


    def notifyDelete(service, nodeIdentifier, subscribers,
                     redirectURI=None):
        """
        Send out node deletion notifications.

        @param service: The entity the notifications will originate from.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node that was deleted.
        @type nodeIdentifier: C{unicode}
        @param subscribers: The subscribers for which a notification should be
            sent out.
        @type subscribers: C{list} of
            L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param redirectURI: Optional XMPP URI of another node that subscribers
            are redirected to.
        @type redirectURI: C{str}
        """

    def publish(requestor, service, nodeIdentifier, items):
        """
        Called when a publish request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node to publish to.
        @type nodeIdentifier: C{unicode}
        @param items: The items to be published as elements.
        @type items: C{list} of C{Element<twisted.words.xish.domish.Element>}
        @return: deferred that fires on success.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def subscribe(requestor, service, nodeIdentifier, subscriber):
        """
        Called when a subscribe request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node to subscribe to.
        @type nodeIdentifier: C{unicode}
        @param subscriber: The entity to be subscribed.
        @type subscriber: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @return: A deferred that fires with a
                 L{Subscription<wokkel.pubsub.Subscription>}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def unsubscribe(requestor, service, nodeIdentifier, subscriber):
        """
        Called when a subscribe request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node to unsubscribe from.
        @type nodeIdentifier: C{unicode}
        @param subscriber: The entity to be unsubscribed.
        @type subscriber: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @return: A deferred that fires with C{None} when unsubscription has
                 succeeded.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def subscriptions(requestor, service):
        """
        Called when a subscriptions retrieval request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @return: A deferred that fires with a C{list} of subscriptions as
                 L{Subscription<wokkel.pubsub.Subscription>}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def affiliations(requestor, service):
        """
        Called when a affiliations retrieval request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @return: A deferred that fires with a C{list} of affiliations as
            C{tuple}s of (node identifier as C{unicode}, affiliation state as
            C{str}). The affiliation can be C{'owner'}, C{'publisher'}, or
            C{'outcast'}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def create(requestor, service, nodeIdentifier):
        """
        Called when a node creation request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The suggestion for the identifier of the node
            to be created. If the request did not include a suggestion for the
            node identifier, the value is C{None}.
        @type nodeIdentifier: C{unicode} or C{NoneType}
        @return: A deferred that fires with a C{unicode} that represents
                 the identifier of the new node.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def getConfigurationOptions():
        """
        Retrieve all known node configuration options.

        The returned dictionary holds the possible node configuration options
        by option name. The value of each entry represents the specifics for
        that option in a dictionary:

         - C{'type'} (C{str}): The option's type (see
           L{Field<wokkel.data_form.Field>}'s doc string for possible values).
         - C{'label'} (C{unicode}): A human readable label for this option.
         - C{'options'} (C{dict}): Optional list of possible values for this
           option.

        Example::

            {
            "pubsub#persist_items":
                {"type": "boolean",
                 "label": "Persist items to storage"},
            "pubsub#deliver_payloads":
                {"type": "boolean",
                 "label": "Deliver payloads with event notifications"},
            "pubsub#send_last_published_item":
                {"type": "list-single",
                 "label": "When to send the last published item",
                 "options": {
                     "never": "Never",
                     "on_sub": "When a new subscription is processed"}
                }
            }

        @rtype: C{dict}.
        """

    def getDefaultConfiguration(requestor, service, nodeType):
        """
        Called when a default node configuration request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeType: The type of node for which the configuration is
                         retrieved, C{'leaf'} or C{'collection'}.
        @type nodeType: C{str}
        @return: A deferred that fires with a C{dict} representing the default
                 node configuration. Keys are C{str}s that represent the
                 field name. Values can be of types C{unicode}, C{int} or
                 C{bool}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def getConfiguration(requestor, service, nodeIdentifier):
        """
        Called when a node configuration retrieval request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node to retrieve the
                               configuration from.
        @type nodeIdentifier: C{unicode}
        @return: A deferred that fires with a C{dict} representing the node
            configuration. Keys are C{str}s that represent the field name.
            Values can be of types C{unicode}, C{int} or C{bool}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def setConfiguration(requestor, service, nodeIdentifier, options):
        """
        Called when a node configuration change request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node to change the
                               configuration of.
        @type nodeIdentifier: C{unicode}
        @return: A deferred that fires with C{None} when the node's
                 configuration has been changed.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """

    def items(requestor, service, nodeIdentifier, maxItems, itemIdentifiers):
        """
        Called when a items retrieval request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node to retrieve items
                               from.
        @type nodeIdentifier: C{unicode}
        """

    def retract(requestor, service, nodeIdentifier, itemIdentifiers):
        """
        Called when a item retraction request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node to retract items
                               from.
        @type nodeIdentifier: C{unicode}
        """

    def purge(requestor, service, nodeIdentifier):
        """
        Called when a node purge request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node to be purged.
        @type nodeIdentifier: C{unicode}
        """

    def delete(requestor, service, nodeIdentifier):
        """
        Called when a node deletion request has been received.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The entity the request was addressed to.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: The identifier of the node to be delete.
        @type nodeIdentifier: C{unicode}
        """



class IPubSubResource(Interface):

    def locateResource(request):
        """
        Locate a resource that will handle the request.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        """


    def getInfo(requestor, service, nodeIdentifier):
        """
        Get node type and meta data.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The publish-subscribe service entity.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: Identifier of the node to request the info for.
        @type nodeIdentifier: C{unicode}
        @return: A deferred that fires with a dictionary. If not empty,
                 it must have the keys C{'type'} and C{'meta-data'} to keep
                 respectively the node type and a dictionary with the meta
                 data for that node.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def getNodes(requestor, service, nodeIdentifier):
        """
        Get all nodes contained by this node.

        @param requestor: The entity the request originated from.
        @type requestor: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param service: The publish-subscribe service entity.
        @type service: L{JID<twisted.words.protocols.jabber.jid.JID>}
        @param nodeIdentifier: Identifier of the node to request the childs
            for.
        @type nodeIdentifier: C{unicode}
        @return: A deferred that fires with a list of child node identifiers.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def getConfigurationOptions():
        """
        Retrieve all known node configuration options.

        The returned dictionary holds the possible node configuration options
        by option name. The value of each entry represents the specifics for
        that option in a dictionary:

         - C{'type'} (C{str}): The option's type (see
           L{Field<wokkel.data_form.Field>}'s doc string for possible values).
         - C{'label'} (C{unicode}): A human readable label for this option.
         - C{'options'} (C{dict}): Optional list of possible values for this
           option.

        Example::

            {
            "pubsub#persist_items":
                {"type": "boolean",
                 "label": "Persist items to storage"},
            "pubsub#deliver_payloads":
                {"type": "boolean",
                 "label": "Deliver payloads with event notifications"},
            "pubsub#send_last_published_item":
                {"type": "list-single",
                 "label": "When to send the last published item",
                 "options": {
                     "never": "Never",
                     "on_sub": "When a new subscription is processed"}
                }
            }

        @rtype: C{dict}.
        """


    def publish(request):
        """
        Called when a publish request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: deferred that fires on success.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def subscribe(request):
        """
        Called when a subscribe request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with a
                 L{Subscription<wokkel.pubsub.Subscription>}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def unsubscribe(request):
        """
        Called when a subscribe request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with C{None} when unsubscription has
                 succeeded.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def subscriptions(request):
        """
        Called when a subscriptions retrieval request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with a C{list} of subscriptions as
                 L{Subscription<wokkel.pubsub.Subscription>}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def affiliations(request):
        """
        Called when a affiliations retrieval request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with a C{list} of affiliations as
            C{tuple}s of (node identifier as C{unicode}, affiliation state as
            C{str}). The affiliation can be C{'owner'}, C{'publisher'}, or
            C{'outcast'}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def create(request):
        """
        Called when a node creation request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with a C{unicode} that represents
                 the identifier of the new node.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def default(request):
        """
        Called when a default node configuration request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with a C{dict} representing the default
                 node configuration. Keys are C{str}s that represent the
                 field name. Values can be of types C{unicode}, C{int} or
                 C{bool}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def configureGet(request):
        """
        Called when a node configuration retrieval request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with a C{dict} representing the node
            configuration. Keys are C{str}s that represent the field name.
            Values can be of types C{unicode}, C{int} or C{bool}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def configureSet(request):
        """
        Called when a node configuration change request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with C{None} when the node's
                 configuration has been changed.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def items(request):
        """
        Called when a items retrieval request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with a C{list} of L{pubsub.Item}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def retract(request):
        """
        Called when a item retraction request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with C{None} when the given items have
                 been retracted.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def purge(request):
        """
        Called when a node purge request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with C{None} when the node has been
                 purged.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def delete(request):
        """
        Called when a node deletion request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with C{None} when the node has been
                 deleted.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}
        """


    def affiliationsGet(request):
        """
        Called when an owner affiliations retrieval request been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}
        @return: A deferred that fires with a C{dict} of affiliations with the
            entity as key (L{JID<twisted.words.protocols.jabber.jid.JID>}) and
            the affiliation state as value (C{unicode}).  The affiliation can
            be C{u'owner'}, C{u'publisher'}, or C{u'outcast'}.
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}

        @note: Affiliations are always on the bare JID. An implementation of
        this method MUST NOT return JIDs with a resource part.
        """


    def affiliationsSet(request):
        """
        Called when a affiliations modify request has been received.

        @param request: The publish-subscribe request.
        @type request: L{wokkel.pubsub.PubSubRequest}

        @return: A deferred that fires with C{None} when the affiliation
            changes were succesfully processed..
        @rtype: L{Deferred<twisted.internet.defer.Deferred>}

        @note: Affiliations are always on the bare JID. The JIDs in
            L{wokkel.pubsub.PubSubRequest}'s C{affiliations} attribute are
            already stripped of any resource.
        """



class IMUCClient(Interface):
    """
    Multi-User Chat Client.

    A client interface to XEP-045 : http://xmpp.org/extensions/xep-0045.html
    """

    def receivedSubject(room, user, subject):
        """
        The room subject has been received.

        A subject is received when you join a room and when the subject is
        changed.

        @param room: The room the subject was accepted for.
        @type room: L{muc.Room}

        @param user: The user that set the subject.
        @type  user: L{muc.User}

        @param subject: The subject of the given room.
        @type subject: C{unicode}
        """


    def receivedHistory(room, user, message):
        """
        Past messages from a chat room have been received.

        This occurs when you join a room.
        """


    def configure(roomJID, options):
        """
        Configure a room.

        @param roomJID: The room to configure.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param options: A mapping of field names to values, or C{None} to
            cancel.
        @type options: C{dict}
        """


    def getConfiguration(roomJID):
        """
        Grab the configuration from the room.

        This sends an iq request to the room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @return: A deferred that fires with the room's configuration form as
            a L{data_form.Form} or C{None} if there are no configuration
            options available.
        """


    def join(roomJID, nick, historyOptions=None, password=None):
        """
        Join a MUC room by sending presence to it.

        @param roomJID: The JID of the room the entity is joining.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The nick name for the entitity joining the room.
        @type nick: C{unicode}

        @param historyOptions: Options for conversation history sent by the
            room upon joining.
        @type historyOptions: L{HistoryOptions}

        @param password: Optional password for the room.
        @type password: C{unicode}

        @return: A deferred that fires when the entity is in the room or an
                 error has occurred.
        """


    def nick(roomJID, nick):
        """
        Change an entity's nick name in a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#changenick

        @param roomJID: The JID of the room, i.e. without a resource.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The new nick name within the room.
        @type nick: C{unicode}
        """


    def leave(roomJID):
        """
        Leave a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#exit

        @param roomJID: The Room JID of the room to leave.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """


    def userJoinedRoom(room, user):
        """
        User has joined a MUC room.

        This method will need to be modified inorder for clients to
        do something when this event occurs.

        @param room: The room the user joined.
        @type  room: L{muc.Room}

        @param user: The user that joined the room.
        @type  user: L{muc.User}
        """


    def groupChat(roomJID, body):
        """
        Send a groupchat message.
        """


    def chat(occupantJID, body):
        """
        Send a private chat message to a user in a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#privatemessage

        @param occupantJID: The Room JID of the other user.
        @type occupantJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """


    def register(roomJID, options):
        """
        Send a request to register for a room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param options: A mapping of field names to values, or C{None} to
            cancel.
        @type options: C{dict}
        """


    def subject(roomJID, subject):
        """
        Change the subject of a MUC room.

        See: http://xmpp.org/extensions/xep-0045.html#subject-mod

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param subject: The subject you want to set.
        @type subject: C{unicode}
        """


    def voice(roomJID):
        """
        Request voice for a moderated room.

        @param roomJID: The room jabber/xmpp entity id.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """


    def history(roomJID, messages):
        """
        Send history to create a MUC based on a one on one chat.

        See: http://xmpp.org/extensions/xep-0045.html#continue

        @param roomJID: The room jabber/xmpp entity id.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param messages: The history to send to the room as an ordered list of
            message, represented by a dictionary with the keys C{'stanza'},
            holding the original stanza a
            L{Element<twisted.words.xish.domish.Element>}, and C{'timestamp'}
            with the timestamp.
        @type messages: C{list} of
            L{Element<twisted.words.xish.domish.Element>}
        """


    def ban(roomJID, entity, reason=None, sender=None):
        """
        Ban a user from a MUC room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param entity: The bare JID of the entity to be banned.
        @type entity: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param reason: The reason for banning the entity.
        @type reason: C{unicode}

        @param sender: The entity sending the request.
        @type sender: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """


    def kick(roomJID, nick, reason=None, sender=None):
        """
        Kick a user from a MUC room.

        @param roomJID: The bare JID of the room.
        @type roomJID: L{JID<twisted.words.protocols.jabber.jid.JID>}

        @param nick: The occupant to be banned.
        @type nick: L{JID<twisted.words.protocols.jabber.jid.JID>} or
            C{unicode}

        @param reason: The reason given for the kick.
        @type reason: C{unicode}

        @param sender: The entity sending the request.
        @type sender: L{JID<twisted.words.protocols.jabber.jid.JID>}
        """



class IMUCStatuses(Interface):
    """
    Interface for a container of Multi-User Chat status conditions.
    """

    def __contains__(key):
        """
        Return if a status exists in the container.
        """


    def __iter__():
        """
        Return an iterator over the status codes.
        """


    def __len__():
        """
        Return the number of status conditions.
        """



__all__ = ['IXMPPHandler', 'IXMPPHandlerCollection',
           'IPubSubClient', 'IPubSubService', 'IPubSubResource',
           'IMUCClient', 'IMUCStatuses']
