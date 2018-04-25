# -*- test-case-name: wokkel.test.test_data_form -*-
#
# Copyright (c) Ralph Meijer.
# See LICENSE for details.

"""
Data Forms.

Support for Data Forms as described in
U{XEP-0004<http://xmpp.org/extensions/xep-0004.html>}, along with support
for Field Standardization for Data Forms as described in
U{XEP-0068<http://xmpp.org/extensions/xep-0068.html>}.
"""

from __future__ import division, absolute_import

from zope.interface import implementer
from zope.interface.common import mapping

from twisted.python.compat import iteritems, unicode, _PY3
from twisted.words.protocols.jabber.jid import JID
from twisted.words.xish import domish

NS_X_DATA = 'jabber:x:data'



class Error(Exception):
    """
    Data Forms error.
    """



class FieldNameRequiredError(Error):
    """
    A field name is required for this field type.
    """



class TooManyValuesError(Error):
    """
    This field is single-value.
    """



class Option(object):
    """
    Data Forms field option.

    @ivar value: Value of this option.
    @type value: L{unicode}
    @ivar label: Optional label for this option.
    @type label: L{unicode} or L{NoneType}
    """

    def __init__(self, value, label=None):
        self.value = value
        self.label = label


    def __repr__(self):
        r = ["Option(", repr(self.value)]
        if self.label:
            r.append(", ")
            r.append(repr(self.label))
        r.append(")")
        return u"".join(r)


    def toElement(self):
        """
        Return the DOM representation of this option.

        @rtype: L{domish.Element}.
        """
        option = domish.Element((NS_X_DATA, 'option'))
        option.addElement('value', content=self.value)
        if self.label:
            option['label'] = self.label
        return option


    @staticmethod
    def fromElement(element):
        valueElements = list(domish.generateElementsQNamed(element.children,
                                                           'value', NS_X_DATA))
        if not valueElements:
            raise Error("Option has no value")

        label = element.getAttribute('label')
        return Option(unicode(valueElements[0]), label)


class Field(object):
    """
    Data Forms field.

    @ivar fieldType: Type of this field. One of C{'boolean'}, C{'fixed'},
                     C{'hidden'}, C{'jid-multi'}, C{'jid-single'},
                     C{'list-multi'}, C{'list-single'}, C{'text-multi'},
                     C{'text-private'}, C{'text-single'}.

                     The default is C{'text-single'}.
    @type fieldType: L{str}
    @ivar var: Field name. Optional if C{fieldType} is C{'fixed'}.
    @type var: L{str}
    @ivar label: Human readable label for this field.
    @type label: L{unicode}
    @ivar values: The values for this field, for multi-valued field
                  types, as a list of L{bool}, L{unicode} or L{JID}.
    @type values: L{list}
    @ivar options: List of possible values to choose from in a response
                   to this form as a list of L{Option}s.
    @type options: L{list}
    @ivar desc: Human readable description for this field.
    @type desc: L{unicode}
    @ivar required: Whether the field is required to be provided in a
                    response to this form.
    @type required: L{bool}
    """

    def __init__(self, fieldType='text-single', var=None, value=None,
                       values=None, options=None, label=None, desc=None,
                       required=False):
        """
        Initialize this field.

        See the identically named instance variables for descriptions.

        If C{value} is not L{None}, it overrides C{values}, setting the
        given value as the only value for this field.
        """

        self.fieldType = fieldType
        self.var = var

        if value is not None:
            self.value = value
        else:
            self.values = values or []

        self.label = label

        try:
            self.options = [Option(optionValue, optionLabel)
                            for optionValue, optionLabel
                            in iteritems(options)]
        except AttributeError:
            self.options = options or []

        self.desc = desc
        self.required = required


    def __repr__(self):
        r = ["Field(fieldType=", repr(self.fieldType)]
        if self.var:
            r.append(", var=")
            r.append(repr(self.var))
        if self.label:
            r.append(", label=")
            r.append(repr(self.label))
        if self.desc:
            r.append(", desc=")
            r.append(repr(self.desc))
        if self.required:
            r.append(", required=")
            r.append(repr(self.required))
        if self.values:
            r.append(", values=")
            r.append(repr(self.values))
        if self.options:
            r.append(", options=")
            r.append(repr(self.options))
        r.append(")")
        return u"".join(r)


    def __value_set(self, value):
        """
        Setter of value property.

        Sets C{value} as the only element of L{values}.

        @type value: L{bool}, L{unicode} or L{JID}
        """
        self.values = [value]


    def __value_get(self):
        """
        Getter of value property.

        Returns the first element of L{values}, if present, or L{None}.
        """

        if self.values:
            return self.values[0]
        else:
            return None


    value = property(__value_get, __value_set, doc="""
            The value for this field, for single-valued field types.

            This is a special property accessing L{values}.  Writing to this
            property empties L{values} and then sets the given value as the
            only element of L{values}.  Reading from this propery returns the
            first element of L{values}.
            """)


    def typeCheck(self):
        """
        Check field properties agains the set field type.
        """
        if self.var is None and self.fieldType != 'fixed':
            raise FieldNameRequiredError()

        if self.values:
            if (self.fieldType not in ('hidden', 'jid-multi', 'list-multi',
                                       'text-multi', None) and
                len(self.values) > 1):
                raise TooManyValuesError()

            newValues = []
            for value in self.values:
                if self.fieldType == 'boolean':
                    if isinstance(value, (str, unicode)):
                        checkValue = value.lower()
                        if not checkValue in ('0', '1', 'false', 'true'):
                            raise ValueError("Not a boolean")
                        value = checkValue in ('1', 'true')
                    value = bool(value)
                elif self.fieldType in ('jid-single', 'jid-multi'):
                    if not hasattr(value, 'full'):
                        value = JID(value)

                newValues.append(value)

            self.values = newValues


    def toElement(self, asForm=False):
        """
        Return the DOM representation of this Field.

        @rtype: L{domish.Element}.
        """

        self.typeCheck()

        field = domish.Element((NS_X_DATA, 'field'))

        if self.fieldType:
            field['type'] = self.fieldType

        if self.var is not None:
            field['var'] = self.var

        for value in self.values:
            if isinstance(value, bool):
                value = unicode(value).lower()
            else:
                value = unicode(value)

            field.addElement('value', content=value)

        if asForm:
            if self.fieldType in ('list-single', 'list-multi'):
                for option in self.options:
                    field.addChild(option.toElement())

            if self.label is not None:
                field['label'] = self.label

            if self.desc is not None:
                field.addElement('desc', content=self.desc)

            if self.required:
                field.addElement('required')

        return field


    @staticmethod
    def _parse_desc(field, element):
        desc = unicode(element)
        if desc:
            field.desc = desc


    @staticmethod
    def _parse_option(field, element):
        field.options.append(Option.fromElement(element))


    @staticmethod
    def _parse_required(field, element):
        field.required = True


    @staticmethod
    def _parse_value(field, element):
        value = unicode(element)
        field.values.append(value)


    @staticmethod
    def fromElement(element):
        field = Field(None)

        for eAttr, fAttr in iteritems({'type': 'fieldType',
                                       'var': 'var',
                                       'label': 'label'}):
            value = element.getAttribute(eAttr)
            if value:
                setattr(field, fAttr, value)


        for child in element.elements():
            if child.uri != NS_X_DATA:
                continue

            func = getattr(Field, '_parse_' + child.name, None)
            if func:
                func(field, child)

        return field


    @staticmethod
    def fromDict(fieldDict):
        """
        Create a field from a dictionary.

        This is a short hand for passing arguments directly on Field object
        creation. The field type is represented by the C{'type'} key. For
        C{'options'} the value is not a list of L{Option}s, but a dictionary
        keyed by value, with an optional label as value.
        """
        kwargs = fieldDict.copy()

        if 'type' in fieldDict:
            kwargs['fieldType'] = fieldDict['type']
            del kwargs['type']

        if 'options' in fieldDict:
            options = []
            for value, label in iteritems(fieldDict['options']):
                options.append(Option(value, label))
            kwargs['options'] = options

        return Field(**kwargs)



@implementer(mapping.IIterableMapping,
             mapping.IEnumerableMapping,
             mapping.IReadMapping,
             mapping.IItemMapping)

class Form(object):
    """
    Data Form.

    There are two similarly named properties of forms. The C{formType} is the
    the so-called type of the form, and is set as the C{'type'} attribute
    on the form's root element.

    The Field Standardization specification in XEP-0068, defines a way to
    provide a context for the field names used in this form, by setting a
    special hidden field named C{'FORM_TYPE'}, to put the names of all
    other fields in the namespace of the value of that field. This namespace
    is recorded in the C{formNamespace} instance variable.

    A L{Form} also acts as read-only dictionary, with the values of fields
    keyed by their name. See L{__getitem__}.

    @ivar formType: Type of form. One of C{'form'}, C{'submit'}, {'cancel'},
                    or {'result'}.
    @type formType: L{str}

    @ivar title: Natural language title of the form.
    @type title: L{unicode}

    @ivar instructions: Natural language instructions as a list of L{unicode}
        strings without line breaks.
    @type instructions: L{list}

    @ivar formNamespace: The optional namespace of the field names for this
        form. This goes in the special field named C{'FORM_TYPE'}, if set.
    @type formNamespace: L{str}

    @ivar fields: Dictionary of named fields. Note that this is meant to be
        used for reading, only. One should use L{addField} or L{makeFields} and
        L{removeField} for adding and removing fields.
    @type fields: L{dict}

    @ivar fieldList: List of all fields, in the order they are added. Like
        C{fields}, this is meant to be used for reading, only.
    @type fieldList: L{list}
    """

    def __init__(self, formType, title=None, instructions=None,
                       formNamespace=None, fields=None):
        self.formType = formType
        self.title = title
        self.instructions = instructions or []
        self.formNamespace = formNamespace

        self.fieldList = []
        self.fields = {}

        if fields:
            for field in fields:
                self.addField(field)

    def __repr__(self):
        r = ["Form(formType=", repr(self.formType)]

        if self.title:
            r.append(", title=")
            r.append(repr(self.title))
        if self.instructions:
            r.append(", instructions=")
            r.append(repr(self.instructions))
        if self.formNamespace:
            r.append(", formNamespace=")
            r.append(repr(self.formNamespace))
        if self.fieldList:
            r.append(", fields=")
            r.append(repr(self.fieldList))
        r.append(")")
        return u"".join(r)


    def addField(self, field):
        """
        Add a field to this form.

        Fields are added in order, and C{fields} is a dictionary of the
        named fields, that is kept in sync only if this method is used for
        adding new fields. Multiple fields with the same name are disallowed.
        """
        if field.var is not None:
            if field.var in self.fields:
                raise Error("Duplicate field %r" % field.var)

            self.fields[field.var] = field

        self.fieldList.append(field)


    def removeField(self, field):
        """
        Remove a field from this form.
        """
        self.fieldList.remove(field)

        if field.var is not None:
            del self.fields[field.var]


    def makeFields(self, values, fieldDefs=None, filterUnknown=True):
        """
        Create fields from values and add them to this form.

        This creates fields from a mapping of name to value(s) and adds them to
        this form. It is typically used for generating outgoing forms.

        If C{fieldDefs} is not L{None}, this is used to fill in
        additional properties of fields, like the field types, labels and
        possible options.

        If C{filterUnknown} is L{True} and C{fieldDefs} is not L{None}, fields
        will only be created from C{values} with a corresponding entry in
        C{fieldDefs}.

        If the field type is unknown, the field type is L{None}. When the form
        is rendered using L{toElement}, these fields will have no C{'type'}
        attribute, and it is up to the receiving party to interpret the values
        properly (e.g. by knowing about the FORM_TYPE in C{formNamespace} and
        the field name).

        @param values: Values to create fields from.
        @type values: L{dict}

        @param fieldDefs: Field definitions as a dictionary. See
            L{wokkel.iwokkel.IPubSubService.getConfigurationOptions}
        @type fieldDefs: L{dict}

        @param filterUnknown: If L{True}, ignore fields that are not in
            C{fieldDefs}.
        @type filterUnknown: L{bool}
        """
        for name, value in iteritems(values):
            fieldDict = {'var': name,
                         'type': None}

            if fieldDefs is not None:
                if name in fieldDefs:
                    fieldDict.update(fieldDefs[name])
                elif filterUnknown:
                    continue

            if isinstance(value, list):
                fieldDict['values'] = value
            else:
                fieldDict['value'] = value

            self.addField(Field.fromDict(fieldDict))


    def toElement(self):
        """
        Return the DOM representation of this Form.

        @rtype: L{domish.Element}
        """
        form = domish.Element((NS_X_DATA, 'x'))
        form['type'] = self.formType

        if self.title:
            form.addElement('title', content=self.title)

        for instruction in self.instructions:
            form.addElement('instructions', content=instruction)

        if self.formNamespace is not None:
            field = Field('hidden', 'FORM_TYPE', self.formNamespace)
            form.addChild(field.toElement())

        for field in self.fieldList:
            form.addChild(field.toElement(self.formType=='form'))

        return form


    @staticmethod
    def _parse_title(form, element):
        title = unicode(element)
        if title:
            form.title = title


    @staticmethod
    def _parse_instructions(form, element):
        instructions = unicode(element)
        if instructions:
            form.instructions.append(instructions)


    @staticmethod
    def _parse_field(form, element):
        field = Field.fromElement(element)
        if (field.var == "FORM_TYPE" and
            field.fieldType == 'hidden' and
            field.value):
            form.formNamespace = field.value
        else:
            form.addField(field)

    @staticmethod
    def fromElement(element):
        if (element.uri, element.name) != ((NS_X_DATA, 'x')):
            raise Error("Element provided is not a Data Form")

        form = Form(element.getAttribute("type"))

        for child in element.elements():
            if child.uri != NS_X_DATA:
                continue

            func = getattr(Form, '_parse_' + child.name, None)
            if func:
                func(form, child)

        return form


    def __iter__(self):
        return iter(self.fields)


    def __len__(self):
        return len(self.fields)


    def __getitem__(self, key):
        """
        Called to implement evaluation of self[key].

        This returns the value of the field with the name in C{key}. For
        multi-value fields, the value is a list, otherwise a single value.

        If a field has no type, and the field has multiple values, the value
        of the list of values. Otherwise, it will be a single value.

        Raises C{KeyError} if there is no field with the name in C{key}.
        """
        field = self.fields[key]

        if (field.fieldType in ('jid-multi', 'list-multi', 'text-multi') or
            (field.fieldType is None and len(field.values) > 1)):
            value = field.values
        else:
            value = field.value

        return value


    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


    def __contains__(self, key):
        return key in self.fields


    def iterkeys(self):
        return iter(self)


    def itervalues(self):
        for key in self:
            yield self[key]


    def iteritems(self):
        for key in self:
            yield (key, self[key])

    if _PY3:
        keys = iterkeys
        values = itervalues
        items = iteritems
    else:
        def keys(self):
            return list(self)


        def values(self):
            return list(self.itervalues())


        def items(self):
            return list(self.iteritems())


    def getValues(self):
        """
        Extract values from the named form fields.

        For all named fields, the corresponding value or values are
        returned in a dictionary keyed by the field name. This is equivalent
        do L{dict(f)}, where C{f} is a L{Form}.

        @see: L{__getitem__}
        @rtype: L{dict}
        """
        return dict(self)


    def typeCheck(self, fieldDefs=None, filterUnknown=False):
        """
        Check values of fields according to the field definition.

        This method walks all named fields to check their values against their
        type, and is typically used for forms received from other entities. The
        field definition in C{fieldDefs} is used to check the field type.

        If C{filterUnknown} is L{True}, fields that are not present in
        C{fieldDefs} are removed from the form.

        If the field type is L{None} (when not set by the sending entity),
        the type from the field definitition is used, or C{'text-single'} if
        that is not set.

        If C{fieldDefs} is None, an empty dictionary is assumed. This is
        useful for coercing boolean and JID values on forms with type
        C{'form'}.

        @param fieldDefs: Field definitions as a dictionary. See
            L{wokkel.iwokkel.IPubSubService.getConfigurationOptions}
        @type fieldDefs: L{dict}

        @param filterUnknown: If L{True}, remove fields that are not in
            C{fieldDefs}.
        @type filterUnknown: L{bool}
        """

        if fieldDefs is None:
            fieldDefs = {}

        filtered = []

        for name, field in iteritems(self.fields):
            if name in fieldDefs:
                fieldDef = fieldDefs[name]
                if 'type' not in fieldDef:
                    fieldDef['type'] = 'text-single'

                if field.fieldType is None:
                    field.fieldType = fieldDef['type']
                elif field.fieldType != fieldDef['type']:
                    raise TypeError("Field type for %r is %r, expected %r" %
                                    (name,
                                     field.fieldType,
                                     fieldDef['type']))
                else:
                    # Field type is correct
                    pass
                field.typeCheck()
            elif filterUnknown:
                filtered.append(field)
            elif field.fieldType is not None:
                field.typeCheck()
            else:
                # Unknown field without type, no checking, no filtering
                pass

        for field in filtered:
            self.removeField(field)



def findForm(element, formNamespace):
    """
    Find a Data Form.

    Look for an element that represents a Data Form with the specified
    form namespace as a child element of the given element.
    """
    if not element:
        return None

    for child in element.elements():
        if (child.uri, child.name) == ((NS_X_DATA, 'x')):
            form = Form.fromElement(child)

            if (form.formNamespace == formNamespace or
                not form.formNamespace and form.formType=='cancel'):
                return form

    return None
