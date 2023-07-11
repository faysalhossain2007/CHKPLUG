#!/usr/bin/env python

import os
import sys
import codecs
import re
import argparse

import HTMLParser
from bs4 import BeautifulSoup
from bs4 import Comment

from collections import Counter

import html2text

import langid
import roman

import UnicodeNormalizer as uni

#####################################
class NonEnglishException(Exception):
    pass

def incrementListItemCallback(m):
	if re.search(r'^[0-9]+$', m.group(0)): #Digit
		return unicode(str(int(m.group(0)) + 1))
	elif re.search(r'^[a-z]$', m.group(0)):
		return u'a' if m.group(0) == u'z' else unicode(str(chr(ord(m.group(0)) + 1)))
	elif re.search(r'^[A-Z]$', m.group(0)):
		return u'A' if m.group(0) == u'Z' else unicode(str(chr(ord(m.group(0)) + 1)))
	else:
		print 'Error', m
	return m

def spaceParenCallback(m):
	return re.sub(r'\)', u') ',  m.group(0))

def spacePunctCallback(m):
	return u'{} {}'.format(m.group(0)[:-1], m.group(0)[-1])

def incrementListItemCallbackRoman(m):
	nRoman = roman.toRoman(roman.fromRoman(m.group(0).upper()) + 1)
	return nRoman if m.group(0)[0].isupper() else nRoman.lower()

class HtmlPreprocessor:

	def __init__(self, filename):
		def loadRawHtml(filename):
			# Try UTF-8
			try:
				return u'\n'.join([line for line in codecs.open(filename, 'rb', 'utf-8') ])
			except UnicodeDecodeError:
				return u'\n'.join([line for line in codecs.open(filename, 'rb', 'windows-1252') ])

		# Load html
		html = loadRawHtml(filename)

		# Unescape the html first, we can have unicode html (e.g., &gt;p&lt; --> <p>)
		html_parser = HTMLParser.HTMLParser()
		html = html_parser.unescape(html)

		# Parse with bs4
		self.soup = BeautifulSoup(html, 'html.parser')

		# There should really be a better way to strip comments:
		comments = self.soup.findAll(text=lambda text:isinstance(text, Comment))
		for comment in comments:
			comment.extract()

		# Holds popup elements that need to be relocated, as they can interrupt sentences
		self.popups = []


	def process(self):
		def isIteratable(element):
			return 'childGenerator' in dir(element)

		def isSkippableElement(element):
			def isSpanScreenReaderOnlyElement(element):
				return element.name == 'span' and element.get('class') is not None and u'sr-only' in element.get('class')
	
			def isIgnoredElement(element):
				return element.name in [u'style', u'script', u'nav', u'video', u'select', u'head', u'header', u'footer']

			def isNavigationLink(element):
				return element.name == 'a' and re.search(r'^<a\s.*>(Learn\sMore|(Back|Return)([\-\s]to[\-\s]Top)?|Skip\sto\s(content|navigation))</a>$', unicode(element), flags=re.IGNORECASE)
			############
			return isSpanScreenReaderOnlyElement(element) or isNavigationLink(element) or isIgnoredElement(element)

		# Most likely pop-up elements if set display:none. These can interrupt the sentence, so we have to relocate the elements
		def isPopupElement(element):
			return element.name in [u'span', u'div'] and element.get('style') is not None and 'display:none' in element.get('style')

		def isListItem(element):
			return element.name == u'li'

		def processHtml(self, element, listItemDepth=0):
			if isIteratable(element):
				if isListItem(element):
					listItemDepth += 1

				for child in element.childGenerator():
					name = getattr(child, "name", None)
					if name is not None: # Container
						if isSkippableElement(child): # Skip parsing this element
							child.extract()
							continue
						# TODO check pop ups
						processHtml(self, child, listItemDepth if not isPopupElement(child) else 0)
						if isPopupElement(child):
							# Create paragraph tag and set aside to insert at end of body
							newTag = self.soup.new_tag('p')
							newTag.append(child.extract())
							self.popups.append(newTag)
							continue
					elif not child.isspace() and listItemDepth > 0:
						# Annotate list items, as we can have paragraphs embedded and we want to associate it correctly!
						BEGIN_TAG = u'&lt;LISTITEM depth="%d"&gt;' % (listItemDepth,)
						child.replaceWith(u''.join([BEGIN_TAG, unicode(child), u'&lt;/LISTITEM&gt;']))

		#####################################
		for child in self.soup.childGenerator():
			processHtml(self, child)

		# Finally, re-insert the popups at the end of the body
		body = self.soup.find('body')
		for element in self.popups:
			body.append(element)

		return unicode(self.soup)

#####################################

class TextPostProcessor:

	def __init__(self, document):
		self.document = document

	def ensureSingleSpaced(self, text):
		return re.sub(r'\s+', u' ', text)
	
	def containsLettersOrNumbers(self, text):
		return bool(re.search(r'\w', text))

	# Detects language for each paragraph and returns max (per document seems less accurate from initial tests)
	def langDetect(self, text):
		langs = [ langid.classify(line)[0] for line in text if len(line.strip()) > 0 ]
		data = Counter(langs)
		return [ l for l,cnt in data.most_common(1) ]


	def handleInlineList(self, text):
		# Just strip for now...
		if re.search(r':\s*(\(\s*([0-9][0-9]?|[A-Za-z]+)\s*\)|([0-9][0-9]?|[A-Za-z])(\s*\)|\.|\\\.))\s*', text):
			text = re.sub(r'\s+(\(\s*([0-9][0-9]?|[A-Za-z]+)\s*\)|([0-9][0-9]?|[A-Za-z])(\s*\)|\.|\\\.))\s*', u' ', text)
		return text

	def postProcess(self):
		def stripPlaintextListFormatters(text):
				text = re.sub(u'(\s+|^)(\*|\-|\+|\\\-|\\\+|\u2022|\u00B7|\u2013|\u25CF|\u2714|>)\s+', u', ', text, re.UNICODE)
				text = re.sub(r'^(,)?\s+', u'', text)
				text = re.sub(r'(\s+|^)([0-9][0-9]?\.)+[0-9][0-9]?\s+', u' ', text)

				text = re.sub(r'(\s+|^)(\(\s*([0-9][0-9]?|[A-Za-z]+)\s*\))\s+', u' ', text)
				text = re.sub(r'([;\.\?:!]\s+|^)([0-9][0-9]?|[A-Za-z])(\s*\)|\.|\\\.)\s+', lambda m: re.sub(r'(\s+|^)([0-9][0-9]?|[A-Za-z])(\s*\)|\.|\\\.)', u' ', m.group(0)), text)

				text = re.sub(r'^([0-9]+\.[0-9]+)+\.?', u' ', text) 
				text = re.sub(r'^\s+', u'', text)
				# FIXME: Fix regular express and remove and not condition
				if re.search(r'(\s+|^)((\*|\-|\+|\\\-|\\\+|\u2022|\u00B7|\u2013|>)|(([0-9][0-9]?\.)+[0-9][0-9]?)|(\(\s*([0-9][0-9]?|[A-Za-z]+)\s*\)|([0-9][0-9]?|[A-Za-z])(\s*\)|\.|\\\.)))\s+', text) and not re.search(r'(\s+|^)([0-9][0-9]?|[A-Za-z])(\s*\)|\.|\\\.)\s+', text):
					return stripPlaintextListFormatters(text)
				return text

		if u'en' not in self.langDetect(self.document):
			raise NonEnglishException('Document is not English')

		res = []
		for i,line in enumerate(self.document):
			# If empty line or doesn't contain any characters, then skip...
			# Note that this also skips lines in languages with other character sets (Russian, Chinese, Korean, Arabic)
			if len(line.strip()) == 0 or not self.containsLettersOrNumbers(line):
				continue

			line = uni.normalize(line)

			# TODO should we exclude non-English paragraphs?
			#if langid.classify(line)[0] != u'en':
			#	continue

			# Remove double white spaces
			line = self.ensureSingleSpaced(line)
			# Fix plural(s)
			line = re.sub(r'\(s\)', u's', line)
			# Replace and/or with and
			line = re.sub(r'\sand/or\s', u' and ', line)

			line = re.sub(r'\\.', u'.', line)

			#Replace URLs
			line = re.sub(r'http(s)?://[^\s]+', u'website_url_lnk', line)
			line = re.sub(r'www\.[^\s]+', u'website_url_lnk', line)

			line = re.sub(r'\s*\|\s*', u'. ', line)
			line = re.sub(r'\s*\.', u'.', line)
			line = re.sub(r'^\s*[\.,;:]\s*', u'', line)
			# Ensure list items spaced after colon ":(1)" --> ": (1)"
			line = re.sub(r':\(', u': (', line)

			# Ensure spaces after end paren (e.g., ")if" --> ") if"
			line = re.sub(r'\)[A-Za-z0-9]', spaceParenCallback, line)
		
			# Just in case we messed anything up before
			line = self.ensureSingleSpaced(line)

			if u':' in line:
				line = self.handleInlineList(line)

			# Remove numbering, such as (1) or 1.2.3
			line = stripPlaintextListFormatters(line)

			# Fix punctuation spacing
			line = re.sub(r'(:,|:\.|:+)', u':', line)
			line = re.sub(r',\.', u',', line)
			line = re.sub(r'(;,|;+)', u';', line)
			line = re.sub(r',+', u',', line)
			line = re.sub(r'(\)\.|;|,)[A-Za-z]', spacePunctCallback, line)
			line = re.sub(r'(\.|\?)[A-Z]', spacePunctCallback, line)

			# Strip any left over headers..
			line = re.sub(r'^\s*#+\s*', u'', line)

			line = self.ensureSingleSpaced(line)
			# Strip white space at beginning of line
			line = re.sub(r'^\s+', u'', line)
			# Don't let lines end with semicolons
			line = re.sub(r';$', u'.', line)

			res.append(line)
		return res


#####################################

class Preprocessor:
	def __init__(self, filename):
		html = HtmlPreprocessor(filename).process()
		h2text = html2text.HTML2Text()
		h2text.body_width = 0
		h2text.ignore_links = True	# Do not include links
		h2text.ignore_images = True	# Do not include images
		h2text.ignore_emphasis = True # Do not include bold and italics formatting
		self.mkdown = h2text.handle(html)


	def parse(self):
		TEXT_TAG = u'TEXT'
		HEADER_TAG = u'HEADER'
		LISTITEM_TAG = u'ITEM'
		ASSOCLI_TAG = u'ASSOCLI'

		def getElementType(text):
			def isHeader(text):
				match = re.search(r'^#+\s+', text)
				return len([ c for c in match.group(0) if c == u'#' ]) if match else 0

			def isListItem(text):
				match = re.search(r'^\s*\*', text)
				return len([ c for c in match.group(0) if c != u'*' ]) / 2 if match else 0
			
			def isAssocListItem(text):
				match = re.search(r'&lt;[/]?LISTITEM(\sdepth="(?P<num>[0-9]+)")?&gt;', text)
				return int(match.group('num')) if match and match.group('num') is not None else 0
				

			#####################################
			hFlag = isHeader(text)
			if hFlag > 0:
				return (HEADER_TAG, hFlag)
			lFlag = isListItem(text)
			if lFlag > 0:
				return (LISTITEM_TAG, lFlag)
			alFlag = isAssocListItem(text)
			if alFlag > 0:
				return (ASSOCLI_TAG, alFlag)

			return (TEXT_TAG, 0)	

		#####################################
		def stripHeader(text): # TODO Replace colons at end with period
			return re.sub(r'^#+\s+', u'', text)
	
		def stripListItemTags(text):
			return re.sub(r'&lt;[/]?LISTITEM(\sdepth="[0-9]+")?&gt;', u'', text)

		def stripListItemChar(text):
			return re.sub(r'^\s*\*\s*', u'', text)

		def sentenceEndsWithColon(text):
			return stripListItemTags(text.strip()).endswith(':')

		def appendToDoc(outputDoc, text):
			etype = getElementType(text)[0]
			if etype == HEADER_TAG:
				appendToDoc(outputDoc, stripHeader(text))
			elif etype in [LISTITEM_TAG, ASSOCLI_TAG] or re.search('^\s*\*', text):
				appendToDoc(outputDoc, stripListItemChar(stripListItemTags(text)))
			else:
				outputDoc.append(text)

		#####################################
		def getNextPar(pars, index):
			while index < len(pars):
				if len(pars[index].strip()) > 0:
					break
				index += 1
			return index

		def nextParIsListItem(pars, index, depth=-1):
			index = getNextPar(pars, index + 1)
			if index >= len(pars):
				return False

			eType,eDepth = getElementType(pars[index])
			return depth == -1 or eDepth > depth if eType in [LISTITEM_TAG, ASSOCLI_TAG] else False

		def uncapitalize(text):
			return text[:1].lower() + text[1:] if text else u''

		# TODO more complex processing to handle "the following information etc/..."
		def handleListItemText(prependText, listItemText):
			if prependText is None:
				return stripHeader(stripListItemChar(stripListItemTags(listItemText)))

			prependText = re.sub(r'\s*:\s*$', u'', prependText) if u'following' not in prependText.lower() else prependText
			text = uncapitalize(stripHeader(stripListItemChar(stripListItemTags(listItemText))))
			return u' '.join([prependText, text])


		#####################################
		# Returns a list of items instead?
		def handleList(outputDoc, pars, index, prependText):
			index = getNextPar(pars, index + 1)
			listDepth = -1
			# Get rest of list
			while index < len(pars):
				element = pars[index]
				if len(element.strip()) == 0: # If blank line ignore...
					appendToDoc(outputDoc, element)
					index += 1
					continue

				eType,eDepth = getElementType(element)
				if listDepth == -1: # Set item depth if not already set
					listDepth = eDepth

				# If not a list item or text associated with a list item and depth is incorrect.
				if eType not in [LISTITEM_TAG, ASSOCLI_TAG] or eDepth != listDepth:
					index -= 1
					break

				if sentenceEndsWithColon(handleListItemText(None, element)) and nextParIsListItem(mkdownPars, index, listDepth):
					index = handleList(outputDoc, pars, index,  handleListItemText(prependText, element))
					continue
				if eType == ASSOCLI_TAG: #TODO Check why None was passed as first param
					appendToDoc(outputDoc, handleListItemText(prependText, element))
				else:
					appendToDoc(outputDoc, handleListItemText(prependText, element))
				index += 1
			return index

		# Hande plaintext multi-line lists. Either must start with same initial token (e.g., To ...), increasing number/enumeration, or end with semi-colon or "; and"
		def handlePlaintextMultilineList(outputDoc, pars, index, prependText):
			def getFirstTok(text):
				if text is None or len(text.strip()) == 0:
					return None
				splitStr = text.strip().split(u' ')
				return splitStr[0] if len(splitStr) >= 1 else None

			def containsLettersOrNumbers(text):
				return bool(re.search(r'\w', text))

			def escapeCharsForRegex(tok):
				tok = re.sub(r'\(', u'\\(', tok)
				tok = re.sub(r'\*', u'\\*', tok)
				return re.sub(r'\)', u'\\)', tok)

			def stripPlaintextListFormatters(text):
				text = re.sub(u'^\s*(\*|\-|\+|\\\-|\\\+|\u2022|\u00B7|\u2013|>)\s*', u' ', text, re.UNICODE)
				text = re.sub(r'^\s*([0-9][0-9]?\.)+[0-9][0-9]?\s*', u' ', text)
				text = re.sub(r'^\s*(\(([0-9][0-9]?|[A-Za-z])\)|([0-9][0-9]?|[A-Za-z])(\)|\.|\\\.))\s*', u' ', text)
				text = re.sub(r';(\s+(and|or))?\s*$', u'; ', text, re.IGNORECASE)
				return text

			def combineText(prependText, appendText):
				ptext = re.sub(r'\s*:\s*$', u'', stripPlaintextListFormatters(prependText.strip())) if u'following' not in prependText.lower() else stripPlaintextListFormatters(prependText.strip())
				etext = uncapitalize(stripPlaintextListFormatters(appendText.strip()))
				return u' '.join([ptext, etext])


			def checkLIType(text, expectedToken=None):
				defaultFResult = (False, None, False) # matchFound, nextExpectedToken, isNextItemLast
				if text.startswith('#') or not containsLettersOrNumbers(text): # This is a header. Headers can't be list items...
					return defaultFResult

				# Match this first if this was our pattern before...
				if expectedToken == u';' and re.search(r';(\s+(and|or))?\s*$', text, re.IGNORECASE):
					return (True, u';', bool(re.search(r';\s+(and|or)\s*$', text, re.IGNORECASE))) # All items must with with ; 

				# Matches *, \\-, \\+, and common unicode bulletpoints (\u2022, \u00B7)
				sresult = re.search(u'^\s*(\*|\-|\+|\\\-|\\\+|\u2022|\u00B7|\u2013|>)\s*', text, re.UNICODE)
				if sresult:
					tok = sresult.group(0).strip()
					if expectedToken is not None and expectedToken != tok:
						return defaultFResult
					return (True, tok, False)

				# Max match is double digits. Highly unlikely they have a list with over 100 items.
				# Matches X.Y.Z
				sresult = re.search(r'^\s*([0-9][0-9]?\.)+[0-9][0-9]?\s*', text)
				if sresult:
					tok = sresult.group(0).strip()
					if expectedToken is not None and expectedToken != tok:
						return defaultFResult
					#Increment
					splt = tok.strip().split('.')
					splt[-1] = unicode(str(int(splt[-1]) + 1))
					return (True, u'.'.join(splt), False)

				# Match roman numerals
				# Matches (x), x), x., x\., where x is a roman numeral between 1-99
				sresult = re.search(r'^\s*(\(\s*(I|II|III|IV|V|VI|VII|VIII|IX|X|XI|XII|XIII|XIV|XV|XVI|XVII|XVIII|XIX|XX|XXI|XXII|XXIII|XXIV|XXV|XXVI|XXVII|XXVIII|XXIX|XXX|XXXI|XXXII|XXXIII|XXXIV|XXXV|XXXVI|XXXVII|XXXVIII|XXXIX|XL|XLI|XLII|XLIII|XLIV|XLV|XLVI|XLVII|XLVIII|XLIX|L|LI|LII|LIII|LIV|LV|LVI|LVII|LVIII|LIX|LX|LXI|LXII|LXIII|LXIV|LXV|LXVI|LXVII|LXVIII|LXIX|LXX|LXXI|LXXII|LXXIII|LXXIV|LXXV|LXXVI|LXXVII|LXXVIII|LXXIX|LXXX|LXXXI|LXXXII|LXXXIII|LXXXIV|LXXXV|LXXXVI|LXXXVII|LXXXVIII|LXXXIX|XC|XCI|XCII|XCIII|XCIV|XCV|XCVI|XCVII|XCVIII|XCIX)\s*\)|(I|II|III|IV|V|VI|VII|VIII|IX|X|XI|XII|XIII|XIV|XV|XVI|XVII|XVIII|XIX|XX|XXI|XXII|XXIII|XXIV|XXV|XXVI|XXVII|XXVIII|XXIX|XXX|XXXI|XXXII|XXXIII|XXXIV|XXXV|XXXVI|XXXVII|XXXVIII|XXXIX|XL|XLI|XLII|XLIII|XLIV|XLV|XLVI|XLVII|XLVIII|XLIX|L|LI|LII|LIII|LIV|LV|LVI|LVII|LVIII|LIX|LX|LXI|LXII|LXIII|LXIV|LXV|LXVI|LXVII|LXVIII|LXIX|LXX|LXXI|LXXII|LXXIII|LXXIV|LXXV|LXXVI|LXXVII|LXXVIII|LXXIX|LXXX|LXXXI|LXXXII|LXXXIII|LXXXIV|LXXXV|LXXXVI|LXXXVII|LXXXVIII|LXXXIX|XC|XCI|XCII|XCIII|XCIV|XCV|XCVI|XCVII|XCVIII|XCIX)(\s*\)|(\\)?\.))\s*', text, flags=re.IGNORECASE)
				if sresult:
					tok = sresult.group(0).strip()
					if expectedToken is not None and expectedToken != tok:
						return defaultFResult
					res = re.sub(r'[IiVvXxLlCc]+', incrementListItemCallbackRoman, tok)
					return (True, res, False)

				# Max match is double digits. Highly unlikely they have a list with over 100 items.
				# Matches (x), x), x., x\., where 0 <= x <= 99 or A <= x <= Z
				sresult = re.search(r'^\s*(\(\s*([0-9][0-9]?|[A-Za-z])\s*\)|([0-9][0-9]?|[A-Za-z])(\s*\)|(\\)?\.))\s*', text)
				if sresult:
					tok = sresult.group(0).strip()
					if expectedToken is not None and expectedToken != tok:
						return defaultFResult
					res = re.sub(r'[0-9A-Za-z]+', incrementListItemCallback, tok)
					return (True, res, False)

				# Matches end of string ; AND/OR
				sresult = re.search(r';(\s+(and|or))?\s*$', text, re.IGNORECASE)
				if sresult:
					if expectedToken is not None and expectedToken != ';':
						return defaultFResult
					return (True, u';', re.search(r';\s+(and|or)\s*$', text, re.IGNORECASE)) # All items must with with ;

				# All words must start with same first token (e.g., We may send your data: To ..., To ...,)
				tok = getFirstTok(text).strip()
				if expectedToken is not None and expectedToken != tok:
					return defaultFResult
				return (True, tok, False)


			##################
			index = getNextPar(pars, index + 1)
			nextTok = None
			breakNextItem = False
			modifiedDoc = False
			while index < len(pars):
				element = pars[index]
				if len(element.strip()) == 0: # If blank line ignore...
					index += 1
					continue

				eType,eDepth = getElementType(element)
				if eType == HEADER_TAG:
					index -= 1
					break
				elif eType == LISTITEM_TAG:
					nindex = handleList(outputDoc, pars, index - 1, prependText)
					if nindex != index:
						modifiedDoc = True
					index = nindex
					break

				# Get first character
				cont,nextTok,breakNextLine = checkLIType(element, nextTok)

				# Do not append, reverse index, and return...
				if not cont:
					index -= 1
					break

				nText = combineText(prependText, element)
				if sentenceEndsWithColon(element):
					nindex = handlePlaintextMultilineList(outputDoc, pars, index, nText)
					if nindex != index:
						modifiedDoc = True
						index = nindex
					else: # CHECKME
						appendToDoc(outputDoc, nText)
						index += 1
				else:
					modifiedDoc = True
					appendToDoc(outputDoc, nText)
					index += 1
	
				if breakNextItem:
					break
				breakNextItem = breakNextLine
	
			if not modifiedDoc:
				appendToDoc(outputDoc, re.sub(r'\s*:\s*$', u'', stripPlaintextListFormatters(prependText.strip())))
			return index


		def processMarkdown(outputDoc, pars, index=0, prependText=None):
			#Ensures that it is not a title heuristics ( > 2 tokens and all caps)
			def ensureNotTitle(text):
				if len(text.strip()) == 0:
					return False
				ncap = [ 1 if t[0].isupper() else 0 for t in text.strip().split(u' ') if len(t) > 0 and t not in [u'a', u'an', u'the', u'and', u'but', u'for', u'on', u'to', u'at', u'by', u'from', u'in', u'into', u'like', u'of', u'near', u'off', u'onto', u'out', u'over', u'past', u'up', u'upon', u'with', u'within', u'without'] ]
				return len(ncap) > 2 and sum(ncap) < len(ncap) # All capital...

			######################################################
			while index < len(pars):
				element = pars[index]
				if len(element.strip()) == 0:
					appendToDoc(outputDoc, element)
					index += 1
					continue
				
				eType,eDepth = getElementType(element)

				if eType == TEXT_TAG:
					if sentenceEndsWithColon(element):
						if nextParIsListItem(mkdownPars, index): # We have a div list items
							index = handleList(outputDoc, pars, index, element)
						elif ensureNotTitle(element): # We have a plaintext list then...
							index = handlePlaintextMultilineList(outputDoc, pars, index, element)
						else:
							appendToDoc(outputDoc, re.sub(r':\s*$', u'.', element))
					else:
						appendToDoc(outputDoc, stripListItemTags(element))
				elif eType == HEADER_TAG:
					# If element is anything other than TEXT_TAG, strip!
					appendToDoc(outputDoc, stripHeader(element))
				elif eType in [LISTITEM_TAG, ASSOCLI_TAG]:
					#print eType, eDepth
					appendToDoc(outputDoc, stripListItemChar(stripListItemTags(element)))
				index += 1

		#####################################
		output = []
		mkdownPars = self.mkdown.split('\n')
		processMarkdown(output, mkdownPars, 0)
		return TextPostProcessor(output).postProcess()


#####################################

def main(filename):
	hprocessor = Preprocessor(filename)
	return hprocessor.parse()

def getOutputFilename(filename, outputDir):
	return os.path.join(outputDir, '{}.txt'.format(os.path.splitext(os.path.basename(filename))[0]))	

def processFile(filename, outputDir=None):
	try:
		outputfilename = '{}.txt'.format(os.path.splitext(os.path.basename(filename))[0])
		if os.path.isfile(outputfilename):
			return

		if outputDir is not None:
			outputfilename = os.path.join(outputDir, outputfilename)
			res = main(filename)
			with codecs.open(outputfilename, 'w', 'utf-8') as outputfile:
				outputfile.write(u'\n'.join(uni.normalize(res)))
	except NonEnglishException:
		with codecs.open('nonenglish_apks.log', 'a', 'utf-8') as logfile:
			logfile.write(filename)
			logfile.write('\n')
		print 'Error: \"{}\" is not English'.format(filename)

def processDirectory(directory, outputDir=None):
	for root,dirs,files in os.walk(directory):
		for f in files:
			print os.path.join(root, f)
			processFile(os.path.join(root, f), outputDir)

if __name__ =='__main__':
	aparser = argparse.ArgumentParser(description='Converts and preprocesses an html privacy policy to plaintext.')
	aparser.add_argument('-i', '--input', type=str, help='Filename or directory containing html privacy policies. ')
	aparser.add_argument('-o', '--outputdir', type=str, help='directory to write output')

	args = aparser.parse_args()
	if args.input is not None:
		if os.path.isfile(args.input):
			processFile(args.input, args.outputdir)
		elif os.path.exists(args.input):
			processDirectory(args.input, args.outputdir)
		else:
			print 'Could not find \"{}\"'.format(args.input)
			sys.exit(1)
	else:
		aparser.print_help(sys.stderr)
		sys.exit(1)
