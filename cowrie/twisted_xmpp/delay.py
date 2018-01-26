# -*- test-case-name: wokkel.test.test_delay -*-
#
# Copyright (c) Ralph Meijer.
# See LICENSE for details.

"""
Delayed Delivery.

Support for comunicating Delayed Delivery information as specified by
U{XEP-0203<http://xmpp.org/extensions/xep-0203.html>} and its predecessor
U{XEP-0091<http://xmpp.org/extensions/xep-0091.html>}.
"""

from __future__ import division, absolute_import

from dateutil.parser import parse
from dateutil.tz import tzutc

from twisted.words.protocols.jabber.jid import InvalidFormat, JID
from twisted.words.xish import domish

NS_DELAY = 'urn:xmpp:delay'
NS_JABBER_DELAY = 'jabber:x:delay'

class Delay(object):
    """
    Delayed Delivery information.

    Instances of this class represent delayed delivery information that can be
    parsed from and rendered into both XEP-0203 and legacy XEP-0091 formats.

    @ivar stamp: The timestamp the stanza was originally sent.
    @type stamp: L{datetime.datetime}
    @ivar sender: The optional entity that originally sent the stanza or
        delayed its delivery.
    @type sender: L{JID}
    """

    def __init__(self, stamp, sender=None):
        self.stamp = stamp
        self.sender = sender


    def toElement(self, legacy=False):
        """
        Render this instance into a domish Element.

        @param legacy: If C{True}, use the legacy XEP-0091 format.
        @type legacy: C{bool}
        """
        if not self.stamp:
            raise ValueError("stamp is required")
        if self.stamp.tzinfo is None:
            raise ValueError("stamp is not offset-aware")

        if legacy:
            element = domish.Element((NS_JABBER_DELAY, 'x'))
            stampFormat = '%Y%m%dT%H:%M:%S'
        else:
            element = domish.Element((NS_DELAY, 'delay'))
            stampFormat = '%Y-%m-%dT%H:%M:%SZ'

        stamp = self.stamp.astimezone(tzutc())
        element['stamp'] = stamp.strftime(stampFormat)

        if self.sender:
            element['from'] = self.sender.full()

        return element


    @staticmethod
    def fromElement(element):
        """
        Create an instance from a domish Element.
        """
        try:
            stamp = parse(element[u'stamp'])

            # Assume UTC if no timezone was given
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=tzutc())
        except (KeyError, ValueError, TypeError):
            stamp = None

        try:
            sender = JID(element[u'from'])
        except (KeyError, InvalidFormat):
            sender = None

        delay = Delay(stamp, sender)
        return delay



class DelayMixin(object):
    """
    Mixin for parsing delayed delivery information from stanzas.

    This can be used as a mixin for subclasses of L{wokkel.generic.Stanza}
    for parsing delayed delivery information. If both XEP-0203 and XEP-0091
    formats are present, the former takes precedence.
    """

    delay = None

    childParsers = {
            (NS_DELAY, 'delay'): '_childParser_delay',
            (NS_JABBER_DELAY, 'x'): '_childParser_legacyDelay',
            }


    def _childParser_delay(self, element):
        self.delay = Delay.fromElement(element)


    def _childParser_legacyDelay(self, element):
        if not self.delay:
            self.delay = Delay.fromElement(element)
