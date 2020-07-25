(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory();
	else if(typeof define === 'function' && define.amd)
		define([], factory);
	else if(typeof exports === 'object')
		exports["EventsTable"] = factory();
	else
		root["EventsTable"] = factory();
})(window, function() {
return /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 2);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, exports, __webpack_require__) {

var __WEBPACK_AMD_DEFINE_ARRAY__, __WEBPACK_AMD_DEFINE_RESULT__;/*!
 * jQuery JavaScript Library v3.5.1
 * https://jquery.com/
 *
 * Includes Sizzle.js
 * https://sizzlejs.com/
 *
 * Copyright JS Foundation and other contributors
 * Released under the MIT license
 * https://jquery.org/license
 *
 * Date: 2020-05-04T22:49Z
 */
( function( global, factory ) {

	"use strict";

	if (  true && typeof module.exports === "object" ) {

		// For CommonJS and CommonJS-like environments where a proper `window`
		// is present, execute the factory and get jQuery.
		// For environments that do not have a `window` with a `document`
		// (such as Node.js), expose a factory as module.exports.
		// This accentuates the need for the creation of a real `window`.
		// e.g. var jQuery = require("jquery")(window);
		// See ticket #14549 for more info.
		module.exports = global.document ?
			factory( global, true ) :
			function( w ) {
				if ( !w.document ) {
					throw new Error( "jQuery requires a window with a document" );
				}
				return factory( w );
			};
	} else {
		factory( global );
	}

// Pass this if window is not defined yet
} )( typeof window !== "undefined" ? window : this, function( window, noGlobal ) {

// Edge <= 12 - 13+, Firefox <=18 - 45+, IE 10 - 11, Safari 5.1 - 9+, iOS 6 - 9.1
// throw exceptions when non-strict code (e.g., ASP.NET 4.5) accesses strict mode
// arguments.callee.caller (trac-13335). But as of jQuery 3.0 (2016), strict mode should be common
// enough that all such attempts are guarded in a try block.
"use strict";

var arr = [];

var getProto = Object.getPrototypeOf;

var slice = arr.slice;

var flat = arr.flat ? function( array ) {
	return arr.flat.call( array );
} : function( array ) {
	return arr.concat.apply( [], array );
};


var push = arr.push;

var indexOf = arr.indexOf;

var class2type = {};

var toString = class2type.toString;

var hasOwn = class2type.hasOwnProperty;

var fnToString = hasOwn.toString;

var ObjectFunctionString = fnToString.call( Object );

var support = {};

var isFunction = function isFunction( obj ) {

      // Support: Chrome <=57, Firefox <=52
      // In some browsers, typeof returns "function" for HTML <object> elements
      // (i.e., `typeof document.createElement( "object" ) === "function"`).
      // We don't want to classify *any* DOM node as a function.
      return typeof obj === "function" && typeof obj.nodeType !== "number";
  };


var isWindow = function isWindow( obj ) {
		return obj != null && obj === obj.window;
	};


var document = window.document;



	var preservedScriptAttributes = {
		type: true,
		src: true,
		nonce: true,
		noModule: true
	};

	function DOMEval( code, node, doc ) {
		doc = doc || document;

		var i, val,
			script = doc.createElement( "script" );

		script.text = code;
		if ( node ) {
			for ( i in preservedScriptAttributes ) {

				// Support: Firefox 64+, Edge 18+
				// Some browsers don't support the "nonce" property on scripts.
				// On the other hand, just using `getAttribute` is not enough as
				// the `nonce` attribute is reset to an empty string whenever it
				// becomes browsing-context connected.
				// See https://github.com/whatwg/html/issues/2369
				// See https://html.spec.whatwg.org/#nonce-attributes
				// The `node.getAttribute` check was added for the sake of
				// `jQuery.globalEval` so that it can fake a nonce-containing node
				// via an object.
				val = node[ i ] || node.getAttribute && node.getAttribute( i );
				if ( val ) {
					script.setAttribute( i, val );
				}
			}
		}
		doc.head.appendChild( script ).parentNode.removeChild( script );
	}


function toType( obj ) {
	if ( obj == null ) {
		return obj + "";
	}

	// Support: Android <=2.3 only (functionish RegExp)
	return typeof obj === "object" || typeof obj === "function" ?
		class2type[ toString.call( obj ) ] || "object" :
		typeof obj;
}
/* global Symbol */
// Defining this global in .eslintrc.json would create a danger of using the global
// unguarded in another place, it seems safer to define global only for this module



var
	version = "3.5.1",

	// Define a local copy of jQuery
	jQuery = function( selector, context ) {

		// The jQuery object is actually just the init constructor 'enhanced'
		// Need init if jQuery is called (just allow error to be thrown if not included)
		return new jQuery.fn.init( selector, context );
	};

jQuery.fn = jQuery.prototype = {

	// The current version of jQuery being used
	jquery: version,

	constructor: jQuery,

	// The default length of a jQuery object is 0
	length: 0,

	toArray: function() {
		return slice.call( this );
	},

	// Get the Nth element in the matched element set OR
	// Get the whole matched element set as a clean array
	get: function( num ) {

		// Return all the elements in a clean array
		if ( num == null ) {
			return slice.call( this );
		}

		// Return just the one element from the set
		return num < 0 ? this[ num + this.length ] : this[ num ];
	},

	// Take an array of elements and push it onto the stack
	// (returning the new matched element set)
	pushStack: function( elems ) {

		// Build a new jQuery matched element set
		var ret = jQuery.merge( this.constructor(), elems );

		// Add the old object onto the stack (as a reference)
		ret.prevObject = this;

		// Return the newly-formed element set
		return ret;
	},

	// Execute a callback for every element in the matched set.
	each: function( callback ) {
		return jQuery.each( this, callback );
	},

	map: function( callback ) {
		return this.pushStack( jQuery.map( this, function( elem, i ) {
			return callback.call( elem, i, elem );
		} ) );
	},

	slice: function() {
		return this.pushStack( slice.apply( this, arguments ) );
	},

	first: function() {
		return this.eq( 0 );
	},

	last: function() {
		return this.eq( -1 );
	},

	even: function() {
		return this.pushStack( jQuery.grep( this, function( _elem, i ) {
			return ( i + 1 ) % 2;
		} ) );
	},

	odd: function() {
		return this.pushStack( jQuery.grep( this, function( _elem, i ) {
			return i % 2;
		} ) );
	},

	eq: function( i ) {
		var len = this.length,
			j = +i + ( i < 0 ? len : 0 );
		return this.pushStack( j >= 0 && j < len ? [ this[ j ] ] : [] );
	},

	end: function() {
		return this.prevObject || this.constructor();
	},

	// For internal use only.
	// Behaves like an Array's method, not like a jQuery method.
	push: push,
	sort: arr.sort,
	splice: arr.splice
};

jQuery.extend = jQuery.fn.extend = function() {
	var options, name, src, copy, copyIsArray, clone,
		target = arguments[ 0 ] || {},
		i = 1,
		length = arguments.length,
		deep = false;

	// Handle a deep copy situation
	if ( typeof target === "boolean" ) {
		deep = target;

		// Skip the boolean and the target
		target = arguments[ i ] || {};
		i++;
	}

	// Handle case when target is a string or something (possible in deep copy)
	if ( typeof target !== "object" && !isFunction( target ) ) {
		target = {};
	}

	// Extend jQuery itself if only one argument is passed
	if ( i === length ) {
		target = this;
		i--;
	}

	for ( ; i < length; i++ ) {

		// Only deal with non-null/undefined values
		if ( ( options = arguments[ i ] ) != null ) {

			// Extend the base object
			for ( name in options ) {
				copy = options[ name ];

				// Prevent Object.prototype pollution
				// Prevent never-ending loop
				if ( name === "__proto__" || target === copy ) {
					continue;
				}

				// Recurse if we're merging plain objects or arrays
				if ( deep && copy && ( jQuery.isPlainObject( copy ) ||
					( copyIsArray = Array.isArray( copy ) ) ) ) {
					src = target[ name ];

					// Ensure proper type for the source value
					if ( copyIsArray && !Array.isArray( src ) ) {
						clone = [];
					} else if ( !copyIsArray && !jQuery.isPlainObject( src ) ) {
						clone = {};
					} else {
						clone = src;
					}
					copyIsArray = false;

					// Never move original objects, clone them
					target[ name ] = jQuery.extend( deep, clone, copy );

				// Don't bring in undefined values
				} else if ( copy !== undefined ) {
					target[ name ] = copy;
				}
			}
		}
	}

	// Return the modified object
	return target;
};

jQuery.extend( {

	// Unique for each copy of jQuery on the page
	expando: "jQuery" + ( version + Math.random() ).replace( /\D/g, "" ),

	// Assume jQuery is ready without the ready module
	isReady: true,

	error: function( msg ) {
		throw new Error( msg );
	},

	noop: function() {},

	isPlainObject: function( obj ) {
		var proto, Ctor;

		// Detect obvious negatives
		// Use toString instead of jQuery.type to catch host objects
		if ( !obj || toString.call( obj ) !== "[object Object]" ) {
			return false;
		}

		proto = getProto( obj );

		// Objects with no prototype (e.g., `Object.create( null )`) are plain
		if ( !proto ) {
			return true;
		}

		// Objects with prototype are plain iff they were constructed by a global Object function
		Ctor = hasOwn.call( proto, "constructor" ) && proto.constructor;
		return typeof Ctor === "function" && fnToString.call( Ctor ) === ObjectFunctionString;
	},

	isEmptyObject: function( obj ) {
		var name;

		for ( name in obj ) {
			return false;
		}
		return true;
	},

	// Evaluates a script in a provided context; falls back to the global one
	// if not specified.
	globalEval: function( code, options, doc ) {
		DOMEval( code, { nonce: options && options.nonce }, doc );
	},

	each: function( obj, callback ) {
		var length, i = 0;

		if ( isArrayLike( obj ) ) {
			length = obj.length;
			for ( ; i < length; i++ ) {
				if ( callback.call( obj[ i ], i, obj[ i ] ) === false ) {
					break;
				}
			}
		} else {
			for ( i in obj ) {
				if ( callback.call( obj[ i ], i, obj[ i ] ) === false ) {
					break;
				}
			}
		}

		return obj;
	},

	// results is for internal usage only
	makeArray: function( arr, results ) {
		var ret = results || [];

		if ( arr != null ) {
			if ( isArrayLike( Object( arr ) ) ) {
				jQuery.merge( ret,
					typeof arr === "string" ?
					[ arr ] : arr
				);
			} else {
				push.call( ret, arr );
			}
		}

		return ret;
	},

	inArray: function( elem, arr, i ) {
		return arr == null ? -1 : indexOf.call( arr, elem, i );
	},

	// Support: Android <=4.0 only, PhantomJS 1 only
	// push.apply(_, arraylike) throws on ancient WebKit
	merge: function( first, second ) {
		var len = +second.length,
			j = 0,
			i = first.length;

		for ( ; j < len; j++ ) {
			first[ i++ ] = second[ j ];
		}

		first.length = i;

		return first;
	},

	grep: function( elems, callback, invert ) {
		var callbackInverse,
			matches = [],
			i = 0,
			length = elems.length,
			callbackExpect = !invert;

		// Go through the array, only saving the items
		// that pass the validator function
		for ( ; i < length; i++ ) {
			callbackInverse = !callback( elems[ i ], i );
			if ( callbackInverse !== callbackExpect ) {
				matches.push( elems[ i ] );
			}
		}

		return matches;
	},

	// arg is for internal usage only
	map: function( elems, callback, arg ) {
		var length, value,
			i = 0,
			ret = [];

		// Go through the array, translating each of the items to their new values
		if ( isArrayLike( elems ) ) {
			length = elems.length;
			for ( ; i < length; i++ ) {
				value = callback( elems[ i ], i, arg );

				if ( value != null ) {
					ret.push( value );
				}
			}

		// Go through every key on the object,
		} else {
			for ( i in elems ) {
				value = callback( elems[ i ], i, arg );

				if ( value != null ) {
					ret.push( value );
				}
			}
		}

		// Flatten any nested arrays
		return flat( ret );
	},

	// A global GUID counter for objects
	guid: 1,

	// jQuery.support is not used in Core but other projects attach their
	// properties to it so it needs to exist.
	support: support
} );

if ( typeof Symbol === "function" ) {
	jQuery.fn[ Symbol.iterator ] = arr[ Symbol.iterator ];
}

// Populate the class2type map
jQuery.each( "Boolean Number String Function Array Date RegExp Object Error Symbol".split( " " ),
function( _i, name ) {
	class2type[ "[object " + name + "]" ] = name.toLowerCase();
} );

function isArrayLike( obj ) {

	// Support: real iOS 8.2 only (not reproducible in simulator)
	// `in` check used to prevent JIT error (gh-2145)
	// hasOwn isn't used here due to false negatives
	// regarding Nodelist length in IE
	var length = !!obj && "length" in obj && obj.length,
		type = toType( obj );

	if ( isFunction( obj ) || isWindow( obj ) ) {
		return false;
	}

	return type === "array" || length === 0 ||
		typeof length === "number" && length > 0 && ( length - 1 ) in obj;
}
var Sizzle =
/*!
 * Sizzle CSS Selector Engine v2.3.5
 * https://sizzlejs.com/
 *
 * Copyright JS Foundation and other contributors
 * Released under the MIT license
 * https://js.foundation/
 *
 * Date: 2020-03-14
 */
( function( window ) {
var i,
	support,
	Expr,
	getText,
	isXML,
	tokenize,
	compile,
	select,
	outermostContext,
	sortInput,
	hasDuplicate,

	// Local document vars
	setDocument,
	document,
	docElem,
	documentIsHTML,
	rbuggyQSA,
	rbuggyMatches,
	matches,
	contains,

	// Instance-specific data
	expando = "sizzle" + 1 * new Date(),
	preferredDoc = window.document,
	dirruns = 0,
	done = 0,
	classCache = createCache(),
	tokenCache = createCache(),
	compilerCache = createCache(),
	nonnativeSelectorCache = createCache(),
	sortOrder = function( a, b ) {
		if ( a === b ) {
			hasDuplicate = true;
		}
		return 0;
	},

	// Instance methods
	hasOwn = ( {} ).hasOwnProperty,
	arr = [],
	pop = arr.pop,
	pushNative = arr.push,
	push = arr.push,
	slice = arr.slice,

	// Use a stripped-down indexOf as it's faster than native
	// https://jsperf.com/thor-indexof-vs-for/5
	indexOf = function( list, elem ) {
		var i = 0,
			len = list.length;
		for ( ; i < len; i++ ) {
			if ( list[ i ] === elem ) {
				return i;
			}
		}
		return -1;
	},

	booleans = "checked|selected|async|autofocus|autoplay|controls|defer|disabled|hidden|" +
		"ismap|loop|multiple|open|readonly|required|scoped",

	// Regular expressions

	// http://www.w3.org/TR/css3-selectors/#whitespace
	whitespace = "[\\x20\\t\\r\\n\\f]",

	// https://www.w3.org/TR/css-syntax-3/#ident-token-diagram
	identifier = "(?:\\\\[\\da-fA-F]{1,6}" + whitespace +
		"?|\\\\[^\\r\\n\\f]|[\\w-]|[^\0-\\x7f])+",

	// Attribute selectors: http://www.w3.org/TR/selectors/#attribute-selectors
	attributes = "\\[" + whitespace + "*(" + identifier + ")(?:" + whitespace +

		// Operator (capture 2)
		"*([*^$|!~]?=)" + whitespace +

		// "Attribute values must be CSS identifiers [capture 5]
		// or strings [capture 3 or capture 4]"
		"*(?:'((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\"|(" + identifier + "))|)" +
		whitespace + "*\\]",

	pseudos = ":(" + identifier + ")(?:\\((" +

		// To reduce the number of selectors needing tokenize in the preFilter, prefer arguments:
		// 1. quoted (capture 3; capture 4 or capture 5)
		"('((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\")|" +

		// 2. simple (capture 6)
		"((?:\\\\.|[^\\\\()[\\]]|" + attributes + ")*)|" +

		// 3. anything else (capture 2)
		".*" +
		")\\)|)",

	// Leading and non-escaped trailing whitespace, capturing some non-whitespace characters preceding the latter
	rwhitespace = new RegExp( whitespace + "+", "g" ),
	rtrim = new RegExp( "^" + whitespace + "+|((?:^|[^\\\\])(?:\\\\.)*)" +
		whitespace + "+$", "g" ),

	rcomma = new RegExp( "^" + whitespace + "*," + whitespace + "*" ),
	rcombinators = new RegExp( "^" + whitespace + "*([>+~]|" + whitespace + ")" + whitespace +
		"*" ),
	rdescend = new RegExp( whitespace + "|>" ),

	rpseudo = new RegExp( pseudos ),
	ridentifier = new RegExp( "^" + identifier + "$" ),

	matchExpr = {
		"ID": new RegExp( "^#(" + identifier + ")" ),
		"CLASS": new RegExp( "^\\.(" + identifier + ")" ),
		"TAG": new RegExp( "^(" + identifier + "|[*])" ),
		"ATTR": new RegExp( "^" + attributes ),
		"PSEUDO": new RegExp( "^" + pseudos ),
		"CHILD": new RegExp( "^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\(" +
			whitespace + "*(even|odd|(([+-]|)(\\d*)n|)" + whitespace + "*(?:([+-]|)" +
			whitespace + "*(\\d+)|))" + whitespace + "*\\)|)", "i" ),
		"bool": new RegExp( "^(?:" + booleans + ")$", "i" ),

		// For use in libraries implementing .is()
		// We use this for POS matching in `select`
		"needsContext": new RegExp( "^" + whitespace +
			"*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\(" + whitespace +
			"*((?:-\\d)?\\d*)" + whitespace + "*\\)|)(?=[^-]|$)", "i" )
	},

	rhtml = /HTML$/i,
	rinputs = /^(?:input|select|textarea|button)$/i,
	rheader = /^h\d$/i,

	rnative = /^[^{]+\{\s*\[native \w/,

	// Easily-parseable/retrievable ID or TAG or CLASS selectors
	rquickExpr = /^(?:#([\w-]+)|(\w+)|\.([\w-]+))$/,

	rsibling = /[+~]/,

	// CSS escapes
	// http://www.w3.org/TR/CSS21/syndata.html#escaped-characters
	runescape = new RegExp( "\\\\[\\da-fA-F]{1,6}" + whitespace + "?|\\\\([^\\r\\n\\f])", "g" ),
	funescape = function( escape, nonHex ) {
		var high = "0x" + escape.slice( 1 ) - 0x10000;

		return nonHex ?

			// Strip the backslash prefix from a non-hex escape sequence
			nonHex :

			// Replace a hexadecimal escape sequence with the encoded Unicode code point
			// Support: IE <=11+
			// For values outside the Basic Multilingual Plane (BMP), manually construct a
			// surrogate pair
			high < 0 ?
				String.fromCharCode( high + 0x10000 ) :
				String.fromCharCode( high >> 10 | 0xD800, high & 0x3FF | 0xDC00 );
	},

	// CSS string/identifier serialization
	// https://drafts.csswg.org/cssom/#common-serializing-idioms
	rcssescape = /([\0-\x1f\x7f]|^-?\d)|^-$|[^\0-\x1f\x7f-\uFFFF\w-]/g,
	fcssescape = function( ch, asCodePoint ) {
		if ( asCodePoint ) {

			// U+0000 NULL becomes U+FFFD REPLACEMENT CHARACTER
			if ( ch === "\0" ) {
				return "\uFFFD";
			}

			// Control characters and (dependent upon position) numbers get escaped as code points
			return ch.slice( 0, -1 ) + "\\" +
				ch.charCodeAt( ch.length - 1 ).toString( 16 ) + " ";
		}

		// Other potentially-special ASCII characters get backslash-escaped
		return "\\" + ch;
	},

	// Used for iframes
	// See setDocument()
	// Removing the function wrapper causes a "Permission Denied"
	// error in IE
	unloadHandler = function() {
		setDocument();
	},

	inDisabledFieldset = addCombinator(
		function( elem ) {
			return elem.disabled === true && elem.nodeName.toLowerCase() === "fieldset";
		},
		{ dir: "parentNode", next: "legend" }
	);

// Optimize for push.apply( _, NodeList )
try {
	push.apply(
		( arr = slice.call( preferredDoc.childNodes ) ),
		preferredDoc.childNodes
	);

	// Support: Android<4.0
	// Detect silently failing push.apply
	// eslint-disable-next-line no-unused-expressions
	arr[ preferredDoc.childNodes.length ].nodeType;
} catch ( e ) {
	push = { apply: arr.length ?

		// Leverage slice if possible
		function( target, els ) {
			pushNative.apply( target, slice.call( els ) );
		} :

		// Support: IE<9
		// Otherwise append directly
		function( target, els ) {
			var j = target.length,
				i = 0;

			// Can't trust NodeList.length
			while ( ( target[ j++ ] = els[ i++ ] ) ) {}
			target.length = j - 1;
		}
	};
}

function Sizzle( selector, context, results, seed ) {
	var m, i, elem, nid, match, groups, newSelector,
		newContext = context && context.ownerDocument,

		// nodeType defaults to 9, since context defaults to document
		nodeType = context ? context.nodeType : 9;

	results = results || [];

	// Return early from calls with invalid selector or context
	if ( typeof selector !== "string" || !selector ||
		nodeType !== 1 && nodeType !== 9 && nodeType !== 11 ) {

		return results;
	}

	// Try to shortcut find operations (as opposed to filters) in HTML documents
	if ( !seed ) {
		setDocument( context );
		context = context || document;

		if ( documentIsHTML ) {

			// If the selector is sufficiently simple, try using a "get*By*" DOM method
			// (excepting DocumentFragment context, where the methods don't exist)
			if ( nodeType !== 11 && ( match = rquickExpr.exec( selector ) ) ) {

				// ID selector
				if ( ( m = match[ 1 ] ) ) {

					// Document context
					if ( nodeType === 9 ) {
						if ( ( elem = context.getElementById( m ) ) ) {

							// Support: IE, Opera, Webkit
							// TODO: identify versions
							// getElementById can match elements by name instead of ID
							if ( elem.id === m ) {
								results.push( elem );
								return results;
							}
						} else {
							return results;
						}

					// Element context
					} else {

						// Support: IE, Opera, Webkit
						// TODO: identify versions
						// getElementById can match elements by name instead of ID
						if ( newContext && ( elem = newContext.getElementById( m ) ) &&
							contains( context, elem ) &&
							elem.id === m ) {

							results.push( elem );
							return results;
						}
					}

				// Type selector
				} else if ( match[ 2 ] ) {
					push.apply( results, context.getElementsByTagName( selector ) );
					return results;

				// Class selector
				} else if ( ( m = match[ 3 ] ) && support.getElementsByClassName &&
					context.getElementsByClassName ) {

					push.apply( results, context.getElementsByClassName( m ) );
					return results;
				}
			}

			// Take advantage of querySelectorAll
			if ( support.qsa &&
				!nonnativeSelectorCache[ selector + " " ] &&
				( !rbuggyQSA || !rbuggyQSA.test( selector ) ) &&

				// Support: IE 8 only
				// Exclude object elements
				( nodeType !== 1 || context.nodeName.toLowerCase() !== "object" ) ) {

				newSelector = selector;
				newContext = context;

				// qSA considers elements outside a scoping root when evaluating child or
				// descendant combinators, which is not what we want.
				// In such cases, we work around the behavior by prefixing every selector in the
				// list with an ID selector referencing the scope context.
				// The technique has to be used as well when a leading combinator is used
				// as such selectors are not recognized by querySelectorAll.
				// Thanks to Andrew Dupont for this technique.
				if ( nodeType === 1 &&
					( rdescend.test( selector ) || rcombinators.test( selector ) ) ) {

					// Expand context for sibling selectors
					newContext = rsibling.test( selector ) && testContext( context.parentNode ) ||
						context;

					// We can use :scope instead of the ID hack if the browser
					// supports it & if we're not changing the context.
					if ( newContext !== context || !support.scope ) {

						// Capture the context ID, setting it first if necessary
						if ( ( nid = context.getAttribute( "id" ) ) ) {
							nid = nid.replace( rcssescape, fcssescape );
						} else {
							context.setAttribute( "id", ( nid = expando ) );
						}
					}

					// Prefix every selector in the list
					groups = tokenize( selector );
					i = groups.length;
					while ( i-- ) {
						groups[ i ] = ( nid ? "#" + nid : ":scope" ) + " " +
							toSelector( groups[ i ] );
					}
					newSelector = groups.join( "," );
				}

				try {
					push.apply( results,
						newContext.querySelectorAll( newSelector )
					);
					return results;
				} catch ( qsaError ) {
					nonnativeSelectorCache( selector, true );
				} finally {
					if ( nid === expando ) {
						context.removeAttribute( "id" );
					}
				}
			}
		}
	}

	// All others
	return select( selector.replace( rtrim, "$1" ), context, results, seed );
}

/**
 * Create key-value caches of limited size
 * @returns {function(string, object)} Returns the Object data after storing it on itself with
 *	property name the (space-suffixed) string and (if the cache is larger than Expr.cacheLength)
 *	deleting the oldest entry
 */
function createCache() {
	var keys = [];

	function cache( key, value ) {

		// Use (key + " ") to avoid collision with native prototype properties (see Issue #157)
		if ( keys.push( key + " " ) > Expr.cacheLength ) {

			// Only keep the most recent entries
			delete cache[ keys.shift() ];
		}
		return ( cache[ key + " " ] = value );
	}
	return cache;
}

/**
 * Mark a function for special use by Sizzle
 * @param {Function} fn The function to mark
 */
function markFunction( fn ) {
	fn[ expando ] = true;
	return fn;
}

/**
 * Support testing using an element
 * @param {Function} fn Passed the created element and returns a boolean result
 */
function assert( fn ) {
	var el = document.createElement( "fieldset" );

	try {
		return !!fn( el );
	} catch ( e ) {
		return false;
	} finally {

		// Remove from its parent by default
		if ( el.parentNode ) {
			el.parentNode.removeChild( el );
		}

		// release memory in IE
		el = null;
	}
}

/**
 * Adds the same handler for all of the specified attrs
 * @param {String} attrs Pipe-separated list of attributes
 * @param {Function} handler The method that will be applied
 */
function addHandle( attrs, handler ) {
	var arr = attrs.split( "|" ),
		i = arr.length;

	while ( i-- ) {
		Expr.attrHandle[ arr[ i ] ] = handler;
	}
}

/**
 * Checks document order of two siblings
 * @param {Element} a
 * @param {Element} b
 * @returns {Number} Returns less than 0 if a precedes b, greater than 0 if a follows b
 */
function siblingCheck( a, b ) {
	var cur = b && a,
		diff = cur && a.nodeType === 1 && b.nodeType === 1 &&
			a.sourceIndex - b.sourceIndex;

	// Use IE sourceIndex if available on both nodes
	if ( diff ) {
		return diff;
	}

	// Check if b follows a
	if ( cur ) {
		while ( ( cur = cur.nextSibling ) ) {
			if ( cur === b ) {
				return -1;
			}
		}
	}

	return a ? 1 : -1;
}

/**
 * Returns a function to use in pseudos for input types
 * @param {String} type
 */
function createInputPseudo( type ) {
	return function( elem ) {
		var name = elem.nodeName.toLowerCase();
		return name === "input" && elem.type === type;
	};
}

/**
 * Returns a function to use in pseudos for buttons
 * @param {String} type
 */
function createButtonPseudo( type ) {
	return function( elem ) {
		var name = elem.nodeName.toLowerCase();
		return ( name === "input" || name === "button" ) && elem.type === type;
	};
}

/**
 * Returns a function to use in pseudos for :enabled/:disabled
 * @param {Boolean} disabled true for :disabled; false for :enabled
 */
function createDisabledPseudo( disabled ) {

	// Known :disabled false positives: fieldset[disabled] > legend:nth-of-type(n+2) :can-disable
	return function( elem ) {

		// Only certain elements can match :enabled or :disabled
		// https://html.spec.whatwg.org/multipage/scripting.html#selector-enabled
		// https://html.spec.whatwg.org/multipage/scripting.html#selector-disabled
		if ( "form" in elem ) {

			// Check for inherited disabledness on relevant non-disabled elements:
			// * listed form-associated elements in a disabled fieldset
			//   https://html.spec.whatwg.org/multipage/forms.html#category-listed
			//   https://html.spec.whatwg.org/multipage/forms.html#concept-fe-disabled
			// * option elements in a disabled optgroup
			//   https://html.spec.whatwg.org/multipage/forms.html#concept-option-disabled
			// All such elements have a "form" property.
			if ( elem.parentNode && elem.disabled === false ) {

				// Option elements defer to a parent optgroup if present
				if ( "label" in elem ) {
					if ( "label" in elem.parentNode ) {
						return elem.parentNode.disabled === disabled;
					} else {
						return elem.disabled === disabled;
					}
				}

				// Support: IE 6 - 11
				// Use the isDisabled shortcut property to check for disabled fieldset ancestors
				return elem.isDisabled === disabled ||

					// Where there is no isDisabled, check manually
					/* jshint -W018 */
					elem.isDisabled !== !disabled &&
					inDisabledFieldset( elem ) === disabled;
			}

			return elem.disabled === disabled;

		// Try to winnow out elements that can't be disabled before trusting the disabled property.
		// Some victims get caught in our net (label, legend, menu, track), but it shouldn't
		// even exist on them, let alone have a boolean value.
		} else if ( "label" in elem ) {
			return elem.disabled === disabled;
		}

		// Remaining elements are neither :enabled nor :disabled
		return false;
	};
}

/**
 * Returns a function to use in pseudos for positionals
 * @param {Function} fn
 */
function createPositionalPseudo( fn ) {
	return markFunction( function( argument ) {
		argument = +argument;
		return markFunction( function( seed, matches ) {
			var j,
				matchIndexes = fn( [], seed.length, argument ),
				i = matchIndexes.length;

			// Match elements found at the specified indexes
			while ( i-- ) {
				if ( seed[ ( j = matchIndexes[ i ] ) ] ) {
					seed[ j ] = !( matches[ j ] = seed[ j ] );
				}
			}
		} );
	} );
}

/**
 * Checks a node for validity as a Sizzle context
 * @param {Element|Object=} context
 * @returns {Element|Object|Boolean} The input node if acceptable, otherwise a falsy value
 */
function testContext( context ) {
	return context && typeof context.getElementsByTagName !== "undefined" && context;
}

// Expose support vars for convenience
support = Sizzle.support = {};

/**
 * Detects XML nodes
 * @param {Element|Object} elem An element or a document
 * @returns {Boolean} True iff elem is a non-HTML XML node
 */
isXML = Sizzle.isXML = function( elem ) {
	var namespace = elem.namespaceURI,
		docElem = ( elem.ownerDocument || elem ).documentElement;

	// Support: IE <=8
	// Assume HTML when documentElement doesn't yet exist, such as inside loading iframes
	// https://bugs.jquery.com/ticket/4833
	return !rhtml.test( namespace || docElem && docElem.nodeName || "HTML" );
};

/**
 * Sets document-related variables once based on the current document
 * @param {Element|Object} [doc] An element or document object to use to set the document
 * @returns {Object} Returns the current document
 */
setDocument = Sizzle.setDocument = function( node ) {
	var hasCompare, subWindow,
		doc = node ? node.ownerDocument || node : preferredDoc;

	// Return early if doc is invalid or already selected
	// Support: IE 11+, Edge 17 - 18+
	// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
	// two documents; shallow comparisons work.
	// eslint-disable-next-line eqeqeq
	if ( doc == document || doc.nodeType !== 9 || !doc.documentElement ) {
		return document;
	}

	// Update global variables
	document = doc;
	docElem = document.documentElement;
	documentIsHTML = !isXML( document );

	// Support: IE 9 - 11+, Edge 12 - 18+
	// Accessing iframe documents after unload throws "permission denied" errors (jQuery #13936)
	// Support: IE 11+, Edge 17 - 18+
	// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
	// two documents; shallow comparisons work.
	// eslint-disable-next-line eqeqeq
	if ( preferredDoc != document &&
		( subWindow = document.defaultView ) && subWindow.top !== subWindow ) {

		// Support: IE 11, Edge
		if ( subWindow.addEventListener ) {
			subWindow.addEventListener( "unload", unloadHandler, false );

		// Support: IE 9 - 10 only
		} else if ( subWindow.attachEvent ) {
			subWindow.attachEvent( "onunload", unloadHandler );
		}
	}

	// Support: IE 8 - 11+, Edge 12 - 18+, Chrome <=16 - 25 only, Firefox <=3.6 - 31 only,
	// Safari 4 - 5 only, Opera <=11.6 - 12.x only
	// IE/Edge & older browsers don't support the :scope pseudo-class.
	// Support: Safari 6.0 only
	// Safari 6.0 supports :scope but it's an alias of :root there.
	support.scope = assert( function( el ) {
		docElem.appendChild( el ).appendChild( document.createElement( "div" ) );
		return typeof el.querySelectorAll !== "undefined" &&
			!el.querySelectorAll( ":scope fieldset div" ).length;
	} );

	/* Attributes
	---------------------------------------------------------------------- */

	// Support: IE<8
	// Verify that getAttribute really returns attributes and not properties
	// (excepting IE8 booleans)
	support.attributes = assert( function( el ) {
		el.className = "i";
		return !el.getAttribute( "className" );
	} );

	/* getElement(s)By*
	---------------------------------------------------------------------- */

	// Check if getElementsByTagName("*") returns only elements
	support.getElementsByTagName = assert( function( el ) {
		el.appendChild( document.createComment( "" ) );
		return !el.getElementsByTagName( "*" ).length;
	} );

	// Support: IE<9
	support.getElementsByClassName = rnative.test( document.getElementsByClassName );

	// Support: IE<10
	// Check if getElementById returns elements by name
	// The broken getElementById methods don't pick up programmatically-set names,
	// so use a roundabout getElementsByName test
	support.getById = assert( function( el ) {
		docElem.appendChild( el ).id = expando;
		return !document.getElementsByName || !document.getElementsByName( expando ).length;
	} );

	// ID filter and find
	if ( support.getById ) {
		Expr.filter[ "ID" ] = function( id ) {
			var attrId = id.replace( runescape, funescape );
			return function( elem ) {
				return elem.getAttribute( "id" ) === attrId;
			};
		};
		Expr.find[ "ID" ] = function( id, context ) {
			if ( typeof context.getElementById !== "undefined" && documentIsHTML ) {
				var elem = context.getElementById( id );
				return elem ? [ elem ] : [];
			}
		};
	} else {
		Expr.filter[ "ID" ] =  function( id ) {
			var attrId = id.replace( runescape, funescape );
			return function( elem ) {
				var node = typeof elem.getAttributeNode !== "undefined" &&
					elem.getAttributeNode( "id" );
				return node && node.value === attrId;
			};
		};

		// Support: IE 6 - 7 only
		// getElementById is not reliable as a find shortcut
		Expr.find[ "ID" ] = function( id, context ) {
			if ( typeof context.getElementById !== "undefined" && documentIsHTML ) {
				var node, i, elems,
					elem = context.getElementById( id );

				if ( elem ) {

					// Verify the id attribute
					node = elem.getAttributeNode( "id" );
					if ( node && node.value === id ) {
						return [ elem ];
					}

					// Fall back on getElementsByName
					elems = context.getElementsByName( id );
					i = 0;
					while ( ( elem = elems[ i++ ] ) ) {
						node = elem.getAttributeNode( "id" );
						if ( node && node.value === id ) {
							return [ elem ];
						}
					}
				}

				return [];
			}
		};
	}

	// Tag
	Expr.find[ "TAG" ] = support.getElementsByTagName ?
		function( tag, context ) {
			if ( typeof context.getElementsByTagName !== "undefined" ) {
				return context.getElementsByTagName( tag );

			// DocumentFragment nodes don't have gEBTN
			} else if ( support.qsa ) {
				return context.querySelectorAll( tag );
			}
		} :

		function( tag, context ) {
			var elem,
				tmp = [],
				i = 0,

				// By happy coincidence, a (broken) gEBTN appears on DocumentFragment nodes too
				results = context.getElementsByTagName( tag );

			// Filter out possible comments
			if ( tag === "*" ) {
				while ( ( elem = results[ i++ ] ) ) {
					if ( elem.nodeType === 1 ) {
						tmp.push( elem );
					}
				}

				return tmp;
			}
			return results;
		};

	// Class
	Expr.find[ "CLASS" ] = support.getElementsByClassName && function( className, context ) {
		if ( typeof context.getElementsByClassName !== "undefined" && documentIsHTML ) {
			return context.getElementsByClassName( className );
		}
	};

	/* QSA/matchesSelector
	---------------------------------------------------------------------- */

	// QSA and matchesSelector support

	// matchesSelector(:active) reports false when true (IE9/Opera 11.5)
	rbuggyMatches = [];

	// qSa(:focus) reports false when true (Chrome 21)
	// We allow this because of a bug in IE8/9 that throws an error
	// whenever `document.activeElement` is accessed on an iframe
	// So, we allow :focus to pass through QSA all the time to avoid the IE error
	// See https://bugs.jquery.com/ticket/13378
	rbuggyQSA = [];

	if ( ( support.qsa = rnative.test( document.querySelectorAll ) ) ) {

		// Build QSA regex
		// Regex strategy adopted from Diego Perini
		assert( function( el ) {

			var input;

			// Select is set to empty string on purpose
			// This is to test IE's treatment of not explicitly
			// setting a boolean content attribute,
			// since its presence should be enough
			// https://bugs.jquery.com/ticket/12359
			docElem.appendChild( el ).innerHTML = "<a id='" + expando + "'></a>" +
				"<select id='" + expando + "-\r\\' msallowcapture=''>" +
				"<option selected=''></option></select>";

			// Support: IE8, Opera 11-12.16
			// Nothing should be selected when empty strings follow ^= or $= or *=
			// The test attribute must be unknown in Opera but "safe" for WinRT
			// https://msdn.microsoft.com/en-us/library/ie/hh465388.aspx#attribute_section
			if ( el.querySelectorAll( "[msallowcapture^='']" ).length ) {
				rbuggyQSA.push( "[*^$]=" + whitespace + "*(?:''|\"\")" );
			}

			// Support: IE8
			// Boolean attributes and "value" are not treated correctly
			if ( !el.querySelectorAll( "[selected]" ).length ) {
				rbuggyQSA.push( "\\[" + whitespace + "*(?:value|" + booleans + ")" );
			}

			// Support: Chrome<29, Android<4.4, Safari<7.0+, iOS<7.0+, PhantomJS<1.9.8+
			if ( !el.querySelectorAll( "[id~=" + expando + "-]" ).length ) {
				rbuggyQSA.push( "~=" );
			}

			// Support: IE 11+, Edge 15 - 18+
			// IE 11/Edge don't find elements on a `[name='']` query in some cases.
			// Adding a temporary attribute to the document before the selection works
			// around the issue.
			// Interestingly, IE 10 & older don't seem to have the issue.
			input = document.createElement( "input" );
			input.setAttribute( "name", "" );
			el.appendChild( input );
			if ( !el.querySelectorAll( "[name='']" ).length ) {
				rbuggyQSA.push( "\\[" + whitespace + "*name" + whitespace + "*=" +
					whitespace + "*(?:''|\"\")" );
			}

			// Webkit/Opera - :checked should return selected option elements
			// http://www.w3.org/TR/2011/REC-css3-selectors-20110929/#checked
			// IE8 throws error here and will not see later tests
			if ( !el.querySelectorAll( ":checked" ).length ) {
				rbuggyQSA.push( ":checked" );
			}

			// Support: Safari 8+, iOS 8+
			// https://bugs.webkit.org/show_bug.cgi?id=136851
			// In-page `selector#id sibling-combinator selector` fails
			if ( !el.querySelectorAll( "a#" + expando + "+*" ).length ) {
				rbuggyQSA.push( ".#.+[+~]" );
			}

			// Support: Firefox <=3.6 - 5 only
			// Old Firefox doesn't throw on a badly-escaped identifier.
			el.querySelectorAll( "\\\f" );
			rbuggyQSA.push( "[\\r\\n\\f]" );
		} );

		assert( function( el ) {
			el.innerHTML = "<a href='' disabled='disabled'></a>" +
				"<select disabled='disabled'><option/></select>";

			// Support: Windows 8 Native Apps
			// The type and name attributes are restricted during .innerHTML assignment
			var input = document.createElement( "input" );
			input.setAttribute( "type", "hidden" );
			el.appendChild( input ).setAttribute( "name", "D" );

			// Support: IE8
			// Enforce case-sensitivity of name attribute
			if ( el.querySelectorAll( "[name=d]" ).length ) {
				rbuggyQSA.push( "name" + whitespace + "*[*^$|!~]?=" );
			}

			// FF 3.5 - :enabled/:disabled and hidden elements (hidden elements are still enabled)
			// IE8 throws error here and will not see later tests
			if ( el.querySelectorAll( ":enabled" ).length !== 2 ) {
				rbuggyQSA.push( ":enabled", ":disabled" );
			}

			// Support: IE9-11+
			// IE's :disabled selector does not pick up the children of disabled fieldsets
			docElem.appendChild( el ).disabled = true;
			if ( el.querySelectorAll( ":disabled" ).length !== 2 ) {
				rbuggyQSA.push( ":enabled", ":disabled" );
			}

			// Support: Opera 10 - 11 only
			// Opera 10-11 does not throw on post-comma invalid pseudos
			el.querySelectorAll( "*,:x" );
			rbuggyQSA.push( ",.*:" );
		} );
	}

	if ( ( support.matchesSelector = rnative.test( ( matches = docElem.matches ||
		docElem.webkitMatchesSelector ||
		docElem.mozMatchesSelector ||
		docElem.oMatchesSelector ||
		docElem.msMatchesSelector ) ) ) ) {

		assert( function( el ) {

			// Check to see if it's possible to do matchesSelector
			// on a disconnected node (IE 9)
			support.disconnectedMatch = matches.call( el, "*" );

			// This should fail with an exception
			// Gecko does not error, returns false instead
			matches.call( el, "[s!='']:x" );
			rbuggyMatches.push( "!=", pseudos );
		} );
	}

	rbuggyQSA = rbuggyQSA.length && new RegExp( rbuggyQSA.join( "|" ) );
	rbuggyMatches = rbuggyMatches.length && new RegExp( rbuggyMatches.join( "|" ) );

	/* Contains
	---------------------------------------------------------------------- */
	hasCompare = rnative.test( docElem.compareDocumentPosition );

	// Element contains another
	// Purposefully self-exclusive
	// As in, an element does not contain itself
	contains = hasCompare || rnative.test( docElem.contains ) ?
		function( a, b ) {
			var adown = a.nodeType === 9 ? a.documentElement : a,
				bup = b && b.parentNode;
			return a === bup || !!( bup && bup.nodeType === 1 && (
				adown.contains ?
					adown.contains( bup ) :
					a.compareDocumentPosition && a.compareDocumentPosition( bup ) & 16
			) );
		} :
		function( a, b ) {
			if ( b ) {
				while ( ( b = b.parentNode ) ) {
					if ( b === a ) {
						return true;
					}
				}
			}
			return false;
		};

	/* Sorting
	---------------------------------------------------------------------- */

	// Document order sorting
	sortOrder = hasCompare ?
	function( a, b ) {

		// Flag for duplicate removal
		if ( a === b ) {
			hasDuplicate = true;
			return 0;
		}

		// Sort on method existence if only one input has compareDocumentPosition
		var compare = !a.compareDocumentPosition - !b.compareDocumentPosition;
		if ( compare ) {
			return compare;
		}

		// Calculate position if both inputs belong to the same document
		// Support: IE 11+, Edge 17 - 18+
		// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
		// two documents; shallow comparisons work.
		// eslint-disable-next-line eqeqeq
		compare = ( a.ownerDocument || a ) == ( b.ownerDocument || b ) ?
			a.compareDocumentPosition( b ) :

			// Otherwise we know they are disconnected
			1;

		// Disconnected nodes
		if ( compare & 1 ||
			( !support.sortDetached && b.compareDocumentPosition( a ) === compare ) ) {

			// Choose the first element that is related to our preferred document
			// Support: IE 11+, Edge 17 - 18+
			// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
			// two documents; shallow comparisons work.
			// eslint-disable-next-line eqeqeq
			if ( a == document || a.ownerDocument == preferredDoc &&
				contains( preferredDoc, a ) ) {
				return -1;
			}

			// Support: IE 11+, Edge 17 - 18+
			// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
			// two documents; shallow comparisons work.
			// eslint-disable-next-line eqeqeq
			if ( b == document || b.ownerDocument == preferredDoc &&
				contains( preferredDoc, b ) ) {
				return 1;
			}

			// Maintain original order
			return sortInput ?
				( indexOf( sortInput, a ) - indexOf( sortInput, b ) ) :
				0;
		}

		return compare & 4 ? -1 : 1;
	} :
	function( a, b ) {

		// Exit early if the nodes are identical
		if ( a === b ) {
			hasDuplicate = true;
			return 0;
		}

		var cur,
			i = 0,
			aup = a.parentNode,
			bup = b.parentNode,
			ap = [ a ],
			bp = [ b ];

		// Parentless nodes are either documents or disconnected
		if ( !aup || !bup ) {

			// Support: IE 11+, Edge 17 - 18+
			// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
			// two documents; shallow comparisons work.
			/* eslint-disable eqeqeq */
			return a == document ? -1 :
				b == document ? 1 :
				/* eslint-enable eqeqeq */
				aup ? -1 :
				bup ? 1 :
				sortInput ?
				( indexOf( sortInput, a ) - indexOf( sortInput, b ) ) :
				0;

		// If the nodes are siblings, we can do a quick check
		} else if ( aup === bup ) {
			return siblingCheck( a, b );
		}

		// Otherwise we need full lists of their ancestors for comparison
		cur = a;
		while ( ( cur = cur.parentNode ) ) {
			ap.unshift( cur );
		}
		cur = b;
		while ( ( cur = cur.parentNode ) ) {
			bp.unshift( cur );
		}

		// Walk down the tree looking for a discrepancy
		while ( ap[ i ] === bp[ i ] ) {
			i++;
		}

		return i ?

			// Do a sibling check if the nodes have a common ancestor
			siblingCheck( ap[ i ], bp[ i ] ) :

			// Otherwise nodes in our document sort first
			// Support: IE 11+, Edge 17 - 18+
			// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
			// two documents; shallow comparisons work.
			/* eslint-disable eqeqeq */
			ap[ i ] == preferredDoc ? -1 :
			bp[ i ] == preferredDoc ? 1 :
			/* eslint-enable eqeqeq */
			0;
	};

	return document;
};

Sizzle.matches = function( expr, elements ) {
	return Sizzle( expr, null, null, elements );
};

Sizzle.matchesSelector = function( elem, expr ) {
	setDocument( elem );

	if ( support.matchesSelector && documentIsHTML &&
		!nonnativeSelectorCache[ expr + " " ] &&
		( !rbuggyMatches || !rbuggyMatches.test( expr ) ) &&
		( !rbuggyQSA     || !rbuggyQSA.test( expr ) ) ) {

		try {
			var ret = matches.call( elem, expr );

			// IE 9's matchesSelector returns false on disconnected nodes
			if ( ret || support.disconnectedMatch ||

				// As well, disconnected nodes are said to be in a document
				// fragment in IE 9
				elem.document && elem.document.nodeType !== 11 ) {
				return ret;
			}
		} catch ( e ) {
			nonnativeSelectorCache( expr, true );
		}
	}

	return Sizzle( expr, document, null, [ elem ] ).length > 0;
};

Sizzle.contains = function( context, elem ) {

	// Set document vars if needed
	// Support: IE 11+, Edge 17 - 18+
	// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
	// two documents; shallow comparisons work.
	// eslint-disable-next-line eqeqeq
	if ( ( context.ownerDocument || context ) != document ) {
		setDocument( context );
	}
	return contains( context, elem );
};

Sizzle.attr = function( elem, name ) {

	// Set document vars if needed
	// Support: IE 11+, Edge 17 - 18+
	// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
	// two documents; shallow comparisons work.
	// eslint-disable-next-line eqeqeq
	if ( ( elem.ownerDocument || elem ) != document ) {
		setDocument( elem );
	}

	var fn = Expr.attrHandle[ name.toLowerCase() ],

		// Don't get fooled by Object.prototype properties (jQuery #13807)
		val = fn && hasOwn.call( Expr.attrHandle, name.toLowerCase() ) ?
			fn( elem, name, !documentIsHTML ) :
			undefined;

	return val !== undefined ?
		val :
		support.attributes || !documentIsHTML ?
			elem.getAttribute( name ) :
			( val = elem.getAttributeNode( name ) ) && val.specified ?
				val.value :
				null;
};

Sizzle.escape = function( sel ) {
	return ( sel + "" ).replace( rcssescape, fcssescape );
};

Sizzle.error = function( msg ) {
	throw new Error( "Syntax error, unrecognized expression: " + msg );
};

/**
 * Document sorting and removing duplicates
 * @param {ArrayLike} results
 */
Sizzle.uniqueSort = function( results ) {
	var elem,
		duplicates = [],
		j = 0,
		i = 0;

	// Unless we *know* we can detect duplicates, assume their presence
	hasDuplicate = !support.detectDuplicates;
	sortInput = !support.sortStable && results.slice( 0 );
	results.sort( sortOrder );

	if ( hasDuplicate ) {
		while ( ( elem = results[ i++ ] ) ) {
			if ( elem === results[ i ] ) {
				j = duplicates.push( i );
			}
		}
		while ( j-- ) {
			results.splice( duplicates[ j ], 1 );
		}
	}

	// Clear input after sorting to release objects
	// See https://github.com/jquery/sizzle/pull/225
	sortInput = null;

	return results;
};

/**
 * Utility function for retrieving the text value of an array of DOM nodes
 * @param {Array|Element} elem
 */
getText = Sizzle.getText = function( elem ) {
	var node,
		ret = "",
		i = 0,
		nodeType = elem.nodeType;

	if ( !nodeType ) {

		// If no nodeType, this is expected to be an array
		while ( ( node = elem[ i++ ] ) ) {

			// Do not traverse comment nodes
			ret += getText( node );
		}
	} else if ( nodeType === 1 || nodeType === 9 || nodeType === 11 ) {

		// Use textContent for elements
		// innerText usage removed for consistency of new lines (jQuery #11153)
		if ( typeof elem.textContent === "string" ) {
			return elem.textContent;
		} else {

			// Traverse its children
			for ( elem = elem.firstChild; elem; elem = elem.nextSibling ) {
				ret += getText( elem );
			}
		}
	} else if ( nodeType === 3 || nodeType === 4 ) {
		return elem.nodeValue;
	}

	// Do not include comment or processing instruction nodes

	return ret;
};

Expr = Sizzle.selectors = {

	// Can be adjusted by the user
	cacheLength: 50,

	createPseudo: markFunction,

	match: matchExpr,

	attrHandle: {},

	find: {},

	relative: {
		">": { dir: "parentNode", first: true },
		" ": { dir: "parentNode" },
		"+": { dir: "previousSibling", first: true },
		"~": { dir: "previousSibling" }
	},

	preFilter: {
		"ATTR": function( match ) {
			match[ 1 ] = match[ 1 ].replace( runescape, funescape );

			// Move the given value to match[3] whether quoted or unquoted
			match[ 3 ] = ( match[ 3 ] || match[ 4 ] ||
				match[ 5 ] || "" ).replace( runescape, funescape );

			if ( match[ 2 ] === "~=" ) {
				match[ 3 ] = " " + match[ 3 ] + " ";
			}

			return match.slice( 0, 4 );
		},

		"CHILD": function( match ) {

			/* matches from matchExpr["CHILD"]
				1 type (only|nth|...)
				2 what (child|of-type)
				3 argument (even|odd|\d*|\d*n([+-]\d+)?|...)
				4 xn-component of xn+y argument ([+-]?\d*n|)
				5 sign of xn-component
				6 x of xn-component
				7 sign of y-component
				8 y of y-component
			*/
			match[ 1 ] = match[ 1 ].toLowerCase();

			if ( match[ 1 ].slice( 0, 3 ) === "nth" ) {

				// nth-* requires argument
				if ( !match[ 3 ] ) {
					Sizzle.error( match[ 0 ] );
				}

				// numeric x and y parameters for Expr.filter.CHILD
				// remember that false/true cast respectively to 0/1
				match[ 4 ] = +( match[ 4 ] ?
					match[ 5 ] + ( match[ 6 ] || 1 ) :
					2 * ( match[ 3 ] === "even" || match[ 3 ] === "odd" ) );
				match[ 5 ] = +( ( match[ 7 ] + match[ 8 ] ) || match[ 3 ] === "odd" );

				// other types prohibit arguments
			} else if ( match[ 3 ] ) {
				Sizzle.error( match[ 0 ] );
			}

			return match;
		},

		"PSEUDO": function( match ) {
			var excess,
				unquoted = !match[ 6 ] && match[ 2 ];

			if ( matchExpr[ "CHILD" ].test( match[ 0 ] ) ) {
				return null;
			}

			// Accept quoted arguments as-is
			if ( match[ 3 ] ) {
				match[ 2 ] = match[ 4 ] || match[ 5 ] || "";

			// Strip excess characters from unquoted arguments
			} else if ( unquoted && rpseudo.test( unquoted ) &&

				// Get excess from tokenize (recursively)
				( excess = tokenize( unquoted, true ) ) &&

				// advance to the next closing parenthesis
				( excess = unquoted.indexOf( ")", unquoted.length - excess ) - unquoted.length ) ) {

				// excess is a negative index
				match[ 0 ] = match[ 0 ].slice( 0, excess );
				match[ 2 ] = unquoted.slice( 0, excess );
			}

			// Return only captures needed by the pseudo filter method (type and argument)
			return match.slice( 0, 3 );
		}
	},

	filter: {

		"TAG": function( nodeNameSelector ) {
			var nodeName = nodeNameSelector.replace( runescape, funescape ).toLowerCase();
			return nodeNameSelector === "*" ?
				function() {
					return true;
				} :
				function( elem ) {
					return elem.nodeName && elem.nodeName.toLowerCase() === nodeName;
				};
		},

		"CLASS": function( className ) {
			var pattern = classCache[ className + " " ];

			return pattern ||
				( pattern = new RegExp( "(^|" + whitespace +
					")" + className + "(" + whitespace + "|$)" ) ) && classCache(
						className, function( elem ) {
							return pattern.test(
								typeof elem.className === "string" && elem.className ||
								typeof elem.getAttribute !== "undefined" &&
									elem.getAttribute( "class" ) ||
								""
							);
				} );
		},

		"ATTR": function( name, operator, check ) {
			return function( elem ) {
				var result = Sizzle.attr( elem, name );

				if ( result == null ) {
					return operator === "!=";
				}
				if ( !operator ) {
					return true;
				}

				result += "";

				/* eslint-disable max-len */

				return operator === "=" ? result === check :
					operator === "!=" ? result !== check :
					operator === "^=" ? check && result.indexOf( check ) === 0 :
					operator === "*=" ? check && result.indexOf( check ) > -1 :
					operator === "$=" ? check && result.slice( -check.length ) === check :
					operator === "~=" ? ( " " + result.replace( rwhitespace, " " ) + " " ).indexOf( check ) > -1 :
					operator === "|=" ? result === check || result.slice( 0, check.length + 1 ) === check + "-" :
					false;
				/* eslint-enable max-len */

			};
		},

		"CHILD": function( type, what, _argument, first, last ) {
			var simple = type.slice( 0, 3 ) !== "nth",
				forward = type.slice( -4 ) !== "last",
				ofType = what === "of-type";

			return first === 1 && last === 0 ?

				// Shortcut for :nth-*(n)
				function( elem ) {
					return !!elem.parentNode;
				} :

				function( elem, _context, xml ) {
					var cache, uniqueCache, outerCache, node, nodeIndex, start,
						dir = simple !== forward ? "nextSibling" : "previousSibling",
						parent = elem.parentNode,
						name = ofType && elem.nodeName.toLowerCase(),
						useCache = !xml && !ofType,
						diff = false;

					if ( parent ) {

						// :(first|last|only)-(child|of-type)
						if ( simple ) {
							while ( dir ) {
								node = elem;
								while ( ( node = node[ dir ] ) ) {
									if ( ofType ?
										node.nodeName.toLowerCase() === name :
										node.nodeType === 1 ) {

										return false;
									}
								}

								// Reverse direction for :only-* (if we haven't yet done so)
								start = dir = type === "only" && !start && "nextSibling";
							}
							return true;
						}

						start = [ forward ? parent.firstChild : parent.lastChild ];

						// non-xml :nth-child(...) stores cache data on `parent`
						if ( forward && useCache ) {

							// Seek `elem` from a previously-cached index

							// ...in a gzip-friendly way
							node = parent;
							outerCache = node[ expando ] || ( node[ expando ] = {} );

							// Support: IE <9 only
							// Defend against cloned attroperties (jQuery gh-1709)
							uniqueCache = outerCache[ node.uniqueID ] ||
								( outerCache[ node.uniqueID ] = {} );

							cache = uniqueCache[ type ] || [];
							nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ];
							diff = nodeIndex && cache[ 2 ];
							node = nodeIndex && parent.childNodes[ nodeIndex ];

							while ( ( node = ++nodeIndex && node && node[ dir ] ||

								// Fallback to seeking `elem` from the start
								( diff = nodeIndex = 0 ) || start.pop() ) ) {

								// When found, cache indexes on `parent` and break
								if ( node.nodeType === 1 && ++diff && node === elem ) {
									uniqueCache[ type ] = [ dirruns, nodeIndex, diff ];
									break;
								}
							}

						} else {

							// Use previously-cached element index if available
							if ( useCache ) {

								// ...in a gzip-friendly way
								node = elem;
								outerCache = node[ expando ] || ( node[ expando ] = {} );

								// Support: IE <9 only
								// Defend against cloned attroperties (jQuery gh-1709)
								uniqueCache = outerCache[ node.uniqueID ] ||
									( outerCache[ node.uniqueID ] = {} );

								cache = uniqueCache[ type ] || [];
								nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ];
								diff = nodeIndex;
							}

							// xml :nth-child(...)
							// or :nth-last-child(...) or :nth(-last)?-of-type(...)
							if ( diff === false ) {

								// Use the same loop as above to seek `elem` from the start
								while ( ( node = ++nodeIndex && node && node[ dir ] ||
									( diff = nodeIndex = 0 ) || start.pop() ) ) {

									if ( ( ofType ?
										node.nodeName.toLowerCase() === name :
										node.nodeType === 1 ) &&
										++diff ) {

										// Cache the index of each encountered element
										if ( useCache ) {
											outerCache = node[ expando ] ||
												( node[ expando ] = {} );

											// Support: IE <9 only
											// Defend against cloned attroperties (jQuery gh-1709)
											uniqueCache = outerCache[ node.uniqueID ] ||
												( outerCache[ node.uniqueID ] = {} );

											uniqueCache[ type ] = [ dirruns, diff ];
										}

										if ( node === elem ) {
											break;
										}
									}
								}
							}
						}

						// Incorporate the offset, then check against cycle size
						diff -= last;
						return diff === first || ( diff % first === 0 && diff / first >= 0 );
					}
				};
		},

		"PSEUDO": function( pseudo, argument ) {

			// pseudo-class names are case-insensitive
			// http://www.w3.org/TR/selectors/#pseudo-classes
			// Prioritize by case sensitivity in case custom pseudos are added with uppercase letters
			// Remember that setFilters inherits from pseudos
			var args,
				fn = Expr.pseudos[ pseudo ] || Expr.setFilters[ pseudo.toLowerCase() ] ||
					Sizzle.error( "unsupported pseudo: " + pseudo );

			// The user may use createPseudo to indicate that
			// arguments are needed to create the filter function
			// just as Sizzle does
			if ( fn[ expando ] ) {
				return fn( argument );
			}

			// But maintain support for old signatures
			if ( fn.length > 1 ) {
				args = [ pseudo, pseudo, "", argument ];
				return Expr.setFilters.hasOwnProperty( pseudo.toLowerCase() ) ?
					markFunction( function( seed, matches ) {
						var idx,
							matched = fn( seed, argument ),
							i = matched.length;
						while ( i-- ) {
							idx = indexOf( seed, matched[ i ] );
							seed[ idx ] = !( matches[ idx ] = matched[ i ] );
						}
					} ) :
					function( elem ) {
						return fn( elem, 0, args );
					};
			}

			return fn;
		}
	},

	pseudos: {

		// Potentially complex pseudos
		"not": markFunction( function( selector ) {

			// Trim the selector passed to compile
			// to avoid treating leading and trailing
			// spaces as combinators
			var input = [],
				results = [],
				matcher = compile( selector.replace( rtrim, "$1" ) );

			return matcher[ expando ] ?
				markFunction( function( seed, matches, _context, xml ) {
					var elem,
						unmatched = matcher( seed, null, xml, [] ),
						i = seed.length;

					// Match elements unmatched by `matcher`
					while ( i-- ) {
						if ( ( elem = unmatched[ i ] ) ) {
							seed[ i ] = !( matches[ i ] = elem );
						}
					}
				} ) :
				function( elem, _context, xml ) {
					input[ 0 ] = elem;
					matcher( input, null, xml, results );

					// Don't keep the element (issue #299)
					input[ 0 ] = null;
					return !results.pop();
				};
		} ),

		"has": markFunction( function( selector ) {
			return function( elem ) {
				return Sizzle( selector, elem ).length > 0;
			};
		} ),

		"contains": markFunction( function( text ) {
			text = text.replace( runescape, funescape );
			return function( elem ) {
				return ( elem.textContent || getText( elem ) ).indexOf( text ) > -1;
			};
		} ),

		// "Whether an element is represented by a :lang() selector
		// is based solely on the element's language value
		// being equal to the identifier C,
		// or beginning with the identifier C immediately followed by "-".
		// The matching of C against the element's language value is performed case-insensitively.
		// The identifier C does not have to be a valid language name."
		// http://www.w3.org/TR/selectors/#lang-pseudo
		"lang": markFunction( function( lang ) {

			// lang value must be a valid identifier
			if ( !ridentifier.test( lang || "" ) ) {
				Sizzle.error( "unsupported lang: " + lang );
			}
			lang = lang.replace( runescape, funescape ).toLowerCase();
			return function( elem ) {
				var elemLang;
				do {
					if ( ( elemLang = documentIsHTML ?
						elem.lang :
						elem.getAttribute( "xml:lang" ) || elem.getAttribute( "lang" ) ) ) {

						elemLang = elemLang.toLowerCase();
						return elemLang === lang || elemLang.indexOf( lang + "-" ) === 0;
					}
				} while ( ( elem = elem.parentNode ) && elem.nodeType === 1 );
				return false;
			};
		} ),

		// Miscellaneous
		"target": function( elem ) {
			var hash = window.location && window.location.hash;
			return hash && hash.slice( 1 ) === elem.id;
		},

		"root": function( elem ) {
			return elem === docElem;
		},

		"focus": function( elem ) {
			return elem === document.activeElement &&
				( !document.hasFocus || document.hasFocus() ) &&
				!!( elem.type || elem.href || ~elem.tabIndex );
		},

		// Boolean properties
		"enabled": createDisabledPseudo( false ),
		"disabled": createDisabledPseudo( true ),

		"checked": function( elem ) {

			// In CSS3, :checked should return both checked and selected elements
			// http://www.w3.org/TR/2011/REC-css3-selectors-20110929/#checked
			var nodeName = elem.nodeName.toLowerCase();
			return ( nodeName === "input" && !!elem.checked ) ||
				( nodeName === "option" && !!elem.selected );
		},

		"selected": function( elem ) {

			// Accessing this property makes selected-by-default
			// options in Safari work properly
			if ( elem.parentNode ) {
				// eslint-disable-next-line no-unused-expressions
				elem.parentNode.selectedIndex;
			}

			return elem.selected === true;
		},

		// Contents
		"empty": function( elem ) {

			// http://www.w3.org/TR/selectors/#empty-pseudo
			// :empty is negated by element (1) or content nodes (text: 3; cdata: 4; entity ref: 5),
			//   but not by others (comment: 8; processing instruction: 7; etc.)
			// nodeType < 6 works because attributes (2) do not appear as children
			for ( elem = elem.firstChild; elem; elem = elem.nextSibling ) {
				if ( elem.nodeType < 6 ) {
					return false;
				}
			}
			return true;
		},

		"parent": function( elem ) {
			return !Expr.pseudos[ "empty" ]( elem );
		},

		// Element/input types
		"header": function( elem ) {
			return rheader.test( elem.nodeName );
		},

		"input": function( elem ) {
			return rinputs.test( elem.nodeName );
		},

		"button": function( elem ) {
			var name = elem.nodeName.toLowerCase();
			return name === "input" && elem.type === "button" || name === "button";
		},

		"text": function( elem ) {
			var attr;
			return elem.nodeName.toLowerCase() === "input" &&
				elem.type === "text" &&

				// Support: IE<8
				// New HTML5 attribute values (e.g., "search") appear with elem.type === "text"
				( ( attr = elem.getAttribute( "type" ) ) == null ||
					attr.toLowerCase() === "text" );
		},

		// Position-in-collection
		"first": createPositionalPseudo( function() {
			return [ 0 ];
		} ),

		"last": createPositionalPseudo( function( _matchIndexes, length ) {
			return [ length - 1 ];
		} ),

		"eq": createPositionalPseudo( function( _matchIndexes, length, argument ) {
			return [ argument < 0 ? argument + length : argument ];
		} ),

		"even": createPositionalPseudo( function( matchIndexes, length ) {
			var i = 0;
			for ( ; i < length; i += 2 ) {
				matchIndexes.push( i );
			}
			return matchIndexes;
		} ),

		"odd": createPositionalPseudo( function( matchIndexes, length ) {
			var i = 1;
			for ( ; i < length; i += 2 ) {
				matchIndexes.push( i );
			}
			return matchIndexes;
		} ),

		"lt": createPositionalPseudo( function( matchIndexes, length, argument ) {
			var i = argument < 0 ?
				argument + length :
				argument > length ?
					length :
					argument;
			for ( ; --i >= 0; ) {
				matchIndexes.push( i );
			}
			return matchIndexes;
		} ),

		"gt": createPositionalPseudo( function( matchIndexes, length, argument ) {
			var i = argument < 0 ? argument + length : argument;
			for ( ; ++i < length; ) {
				matchIndexes.push( i );
			}
			return matchIndexes;
		} )
	}
};

Expr.pseudos[ "nth" ] = Expr.pseudos[ "eq" ];

// Add button/input type pseudos
for ( i in { radio: true, checkbox: true, file: true, password: true, image: true } ) {
	Expr.pseudos[ i ] = createInputPseudo( i );
}
for ( i in { submit: true, reset: true } ) {
	Expr.pseudos[ i ] = createButtonPseudo( i );
}

// Easy API for creating new setFilters
function setFilters() {}
setFilters.prototype = Expr.filters = Expr.pseudos;
Expr.setFilters = new setFilters();

tokenize = Sizzle.tokenize = function( selector, parseOnly ) {
	var matched, match, tokens, type,
		soFar, groups, preFilters,
		cached = tokenCache[ selector + " " ];

	if ( cached ) {
		return parseOnly ? 0 : cached.slice( 0 );
	}

	soFar = selector;
	groups = [];
	preFilters = Expr.preFilter;

	while ( soFar ) {

		// Comma and first run
		if ( !matched || ( match = rcomma.exec( soFar ) ) ) {
			if ( match ) {

				// Don't consume trailing commas as valid
				soFar = soFar.slice( match[ 0 ].length ) || soFar;
			}
			groups.push( ( tokens = [] ) );
		}

		matched = false;

		// Combinators
		if ( ( match = rcombinators.exec( soFar ) ) ) {
			matched = match.shift();
			tokens.push( {
				value: matched,

				// Cast descendant combinators to space
				type: match[ 0 ].replace( rtrim, " " )
			} );
			soFar = soFar.slice( matched.length );
		}

		// Filters
		for ( type in Expr.filter ) {
			if ( ( match = matchExpr[ type ].exec( soFar ) ) && ( !preFilters[ type ] ||
				( match = preFilters[ type ]( match ) ) ) ) {
				matched = match.shift();
				tokens.push( {
					value: matched,
					type: type,
					matches: match
				} );
				soFar = soFar.slice( matched.length );
			}
		}

		if ( !matched ) {
			break;
		}
	}

	// Return the length of the invalid excess
	// if we're just parsing
	// Otherwise, throw an error or return tokens
	return parseOnly ?
		soFar.length :
		soFar ?
			Sizzle.error( selector ) :

			// Cache the tokens
			tokenCache( selector, groups ).slice( 0 );
};

function toSelector( tokens ) {
	var i = 0,
		len = tokens.length,
		selector = "";
	for ( ; i < len; i++ ) {
		selector += tokens[ i ].value;
	}
	return selector;
}

function addCombinator( matcher, combinator, base ) {
	var dir = combinator.dir,
		skip = combinator.next,
		key = skip || dir,
		checkNonElements = base && key === "parentNode",
		doneName = done++;

	return combinator.first ?

		// Check against closest ancestor/preceding element
		function( elem, context, xml ) {
			while ( ( elem = elem[ dir ] ) ) {
				if ( elem.nodeType === 1 || checkNonElements ) {
					return matcher( elem, context, xml );
				}
			}
			return false;
		} :

		// Check against all ancestor/preceding elements
		function( elem, context, xml ) {
			var oldCache, uniqueCache, outerCache,
				newCache = [ dirruns, doneName ];

			// We can't set arbitrary data on XML nodes, so they don't benefit from combinator caching
			if ( xml ) {
				while ( ( elem = elem[ dir ] ) ) {
					if ( elem.nodeType === 1 || checkNonElements ) {
						if ( matcher( elem, context, xml ) ) {
							return true;
						}
					}
				}
			} else {
				while ( ( elem = elem[ dir ] ) ) {
					if ( elem.nodeType === 1 || checkNonElements ) {
						outerCache = elem[ expando ] || ( elem[ expando ] = {} );

						// Support: IE <9 only
						// Defend against cloned attroperties (jQuery gh-1709)
						uniqueCache = outerCache[ elem.uniqueID ] ||
							( outerCache[ elem.uniqueID ] = {} );

						if ( skip && skip === elem.nodeName.toLowerCase() ) {
							elem = elem[ dir ] || elem;
						} else if ( ( oldCache = uniqueCache[ key ] ) &&
							oldCache[ 0 ] === dirruns && oldCache[ 1 ] === doneName ) {

							// Assign to newCache so results back-propagate to previous elements
							return ( newCache[ 2 ] = oldCache[ 2 ] );
						} else {

							// Reuse newcache so results back-propagate to previous elements
							uniqueCache[ key ] = newCache;

							// A match means we're done; a fail means we have to keep checking
							if ( ( newCache[ 2 ] = matcher( elem, context, xml ) ) ) {
								return true;
							}
						}
					}
				}
			}
			return false;
		};
}

function elementMatcher( matchers ) {
	return matchers.length > 1 ?
		function( elem, context, xml ) {
			var i = matchers.length;
			while ( i-- ) {
				if ( !matchers[ i ]( elem, context, xml ) ) {
					return false;
				}
			}
			return true;
		} :
		matchers[ 0 ];
}

function multipleContexts( selector, contexts, results ) {
	var i = 0,
		len = contexts.length;
	for ( ; i < len; i++ ) {
		Sizzle( selector, contexts[ i ], results );
	}
	return results;
}

function condense( unmatched, map, filter, context, xml ) {
	var elem,
		newUnmatched = [],
		i = 0,
		len = unmatched.length,
		mapped = map != null;

	for ( ; i < len; i++ ) {
		if ( ( elem = unmatched[ i ] ) ) {
			if ( !filter || filter( elem, context, xml ) ) {
				newUnmatched.push( elem );
				if ( mapped ) {
					map.push( i );
				}
			}
		}
	}

	return newUnmatched;
}

function setMatcher( preFilter, selector, matcher, postFilter, postFinder, postSelector ) {
	if ( postFilter && !postFilter[ expando ] ) {
		postFilter = setMatcher( postFilter );
	}
	if ( postFinder && !postFinder[ expando ] ) {
		postFinder = setMatcher( postFinder, postSelector );
	}
	return markFunction( function( seed, results, context, xml ) {
		var temp, i, elem,
			preMap = [],
			postMap = [],
			preexisting = results.length,

			// Get initial elements from seed or context
			elems = seed || multipleContexts(
				selector || "*",
				context.nodeType ? [ context ] : context,
				[]
			),

			// Prefilter to get matcher input, preserving a map for seed-results synchronization
			matcherIn = preFilter && ( seed || !selector ) ?
				condense( elems, preMap, preFilter, context, xml ) :
				elems,

			matcherOut = matcher ?

				// If we have a postFinder, or filtered seed, or non-seed postFilter or preexisting results,
				postFinder || ( seed ? preFilter : preexisting || postFilter ) ?

					// ...intermediate processing is necessary
					[] :

					// ...otherwise use results directly
					results :
				matcherIn;

		// Find primary matches
		if ( matcher ) {
			matcher( matcherIn, matcherOut, context, xml );
		}

		// Apply postFilter
		if ( postFilter ) {
			temp = condense( matcherOut, postMap );
			postFilter( temp, [], context, xml );

			// Un-match failing elements by moving them back to matcherIn
			i = temp.length;
			while ( i-- ) {
				if ( ( elem = temp[ i ] ) ) {
					matcherOut[ postMap[ i ] ] = !( matcherIn[ postMap[ i ] ] = elem );
				}
			}
		}

		if ( seed ) {
			if ( postFinder || preFilter ) {
				if ( postFinder ) {

					// Get the final matcherOut by condensing this intermediate into postFinder contexts
					temp = [];
					i = matcherOut.length;
					while ( i-- ) {
						if ( ( elem = matcherOut[ i ] ) ) {

							// Restore matcherIn since elem is not yet a final match
							temp.push( ( matcherIn[ i ] = elem ) );
						}
					}
					postFinder( null, ( matcherOut = [] ), temp, xml );
				}

				// Move matched elements from seed to results to keep them synchronized
				i = matcherOut.length;
				while ( i-- ) {
					if ( ( elem = matcherOut[ i ] ) &&
						( temp = postFinder ? indexOf( seed, elem ) : preMap[ i ] ) > -1 ) {

						seed[ temp ] = !( results[ temp ] = elem );
					}
				}
			}

		// Add elements to results, through postFinder if defined
		} else {
			matcherOut = condense(
				matcherOut === results ?
					matcherOut.splice( preexisting, matcherOut.length ) :
					matcherOut
			);
			if ( postFinder ) {
				postFinder( null, results, matcherOut, xml );
			} else {
				push.apply( results, matcherOut );
			}
		}
	} );
}

function matcherFromTokens( tokens ) {
	var checkContext, matcher, j,
		len = tokens.length,
		leadingRelative = Expr.relative[ tokens[ 0 ].type ],
		implicitRelative = leadingRelative || Expr.relative[ " " ],
		i = leadingRelative ? 1 : 0,

		// The foundational matcher ensures that elements are reachable from top-level context(s)
		matchContext = addCombinator( function( elem ) {
			return elem === checkContext;
		}, implicitRelative, true ),
		matchAnyContext = addCombinator( function( elem ) {
			return indexOf( checkContext, elem ) > -1;
		}, implicitRelative, true ),
		matchers = [ function( elem, context, xml ) {
			var ret = ( !leadingRelative && ( xml || context !== outermostContext ) ) || (
				( checkContext = context ).nodeType ?
					matchContext( elem, context, xml ) :
					matchAnyContext( elem, context, xml ) );

			// Avoid hanging onto element (issue #299)
			checkContext = null;
			return ret;
		} ];

	for ( ; i < len; i++ ) {
		if ( ( matcher = Expr.relative[ tokens[ i ].type ] ) ) {
			matchers = [ addCombinator( elementMatcher( matchers ), matcher ) ];
		} else {
			matcher = Expr.filter[ tokens[ i ].type ].apply( null, tokens[ i ].matches );

			// Return special upon seeing a positional matcher
			if ( matcher[ expando ] ) {

				// Find the next relative operator (if any) for proper handling
				j = ++i;
				for ( ; j < len; j++ ) {
					if ( Expr.relative[ tokens[ j ].type ] ) {
						break;
					}
				}
				return setMatcher(
					i > 1 && elementMatcher( matchers ),
					i > 1 && toSelector(

					// If the preceding token was a descendant combinator, insert an implicit any-element `*`
					tokens
						.slice( 0, i - 1 )
						.concat( { value: tokens[ i - 2 ].type === " " ? "*" : "" } )
					).replace( rtrim, "$1" ),
					matcher,
					i < j && matcherFromTokens( tokens.slice( i, j ) ),
					j < len && matcherFromTokens( ( tokens = tokens.slice( j ) ) ),
					j < len && toSelector( tokens )
				);
			}
			matchers.push( matcher );
		}
	}

	return elementMatcher( matchers );
}

function matcherFromGroupMatchers( elementMatchers, setMatchers ) {
	var bySet = setMatchers.length > 0,
		byElement = elementMatchers.length > 0,
		superMatcher = function( seed, context, xml, results, outermost ) {
			var elem, j, matcher,
				matchedCount = 0,
				i = "0",
				unmatched = seed && [],
				setMatched = [],
				contextBackup = outermostContext,

				// We must always have either seed elements or outermost context
				elems = seed || byElement && Expr.find[ "TAG" ]( "*", outermost ),

				// Use integer dirruns iff this is the outermost matcher
				dirrunsUnique = ( dirruns += contextBackup == null ? 1 : Math.random() || 0.1 ),
				len = elems.length;

			if ( outermost ) {

				// Support: IE 11+, Edge 17 - 18+
				// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
				// two documents; shallow comparisons work.
				// eslint-disable-next-line eqeqeq
				outermostContext = context == document || context || outermost;
			}

			// Add elements passing elementMatchers directly to results
			// Support: IE<9, Safari
			// Tolerate NodeList properties (IE: "length"; Safari: <number>) matching elements by id
			for ( ; i !== len && ( elem = elems[ i ] ) != null; i++ ) {
				if ( byElement && elem ) {
					j = 0;

					// Support: IE 11+, Edge 17 - 18+
					// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
					// two documents; shallow comparisons work.
					// eslint-disable-next-line eqeqeq
					if ( !context && elem.ownerDocument != document ) {
						setDocument( elem );
						xml = !documentIsHTML;
					}
					while ( ( matcher = elementMatchers[ j++ ] ) ) {
						if ( matcher( elem, context || document, xml ) ) {
							results.push( elem );
							break;
						}
					}
					if ( outermost ) {
						dirruns = dirrunsUnique;
					}
				}

				// Track unmatched elements for set filters
				if ( bySet ) {

					// They will have gone through all possible matchers
					if ( ( elem = !matcher && elem ) ) {
						matchedCount--;
					}

					// Lengthen the array for every element, matched or not
					if ( seed ) {
						unmatched.push( elem );
					}
				}
			}

			// `i` is now the count of elements visited above, and adding it to `matchedCount`
			// makes the latter nonnegative.
			matchedCount += i;

			// Apply set filters to unmatched elements
			// NOTE: This can be skipped if there are no unmatched elements (i.e., `matchedCount`
			// equals `i`), unless we didn't visit _any_ elements in the above loop because we have
			// no element matchers and no seed.
			// Incrementing an initially-string "0" `i` allows `i` to remain a string only in that
			// case, which will result in a "00" `matchedCount` that differs from `i` but is also
			// numerically zero.
			if ( bySet && i !== matchedCount ) {
				j = 0;
				while ( ( matcher = setMatchers[ j++ ] ) ) {
					matcher( unmatched, setMatched, context, xml );
				}

				if ( seed ) {

					// Reintegrate element matches to eliminate the need for sorting
					if ( matchedCount > 0 ) {
						while ( i-- ) {
							if ( !( unmatched[ i ] || setMatched[ i ] ) ) {
								setMatched[ i ] = pop.call( results );
							}
						}
					}

					// Discard index placeholder values to get only actual matches
					setMatched = condense( setMatched );
				}

				// Add matches to results
				push.apply( results, setMatched );

				// Seedless set matches succeeding multiple successful matchers stipulate sorting
				if ( outermost && !seed && setMatched.length > 0 &&
					( matchedCount + setMatchers.length ) > 1 ) {

					Sizzle.uniqueSort( results );
				}
			}

			// Override manipulation of globals by nested matchers
			if ( outermost ) {
				dirruns = dirrunsUnique;
				outermostContext = contextBackup;
			}

			return unmatched;
		};

	return bySet ?
		markFunction( superMatcher ) :
		superMatcher;
}

compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) {
	var i,
		setMatchers = [],
		elementMatchers = [],
		cached = compilerCache[ selector + " " ];

	if ( !cached ) {

		// Generate a function of recursive functions that can be used to check each element
		if ( !match ) {
			match = tokenize( selector );
		}
		i = match.length;
		while ( i-- ) {
			cached = matcherFromTokens( match[ i ] );
			if ( cached[ expando ] ) {
				setMatchers.push( cached );
			} else {
				elementMatchers.push( cached );
			}
		}

		// Cache the compiled function
		cached = compilerCache(
			selector,
			matcherFromGroupMatchers( elementMatchers, setMatchers )
		);

		// Save selector and tokenization
		cached.selector = selector;
	}
	return cached;
};

/**
 * A low-level selection function that works with Sizzle's compiled
 *  selector functions
 * @param {String|Function} selector A selector or a pre-compiled
 *  selector function built with Sizzle.compile
 * @param {Element} context
 * @param {Array} [results]
 * @param {Array} [seed] A set of elements to match against
 */
select = Sizzle.select = function( selector, context, results, seed ) {
	var i, tokens, token, type, find,
		compiled = typeof selector === "function" && selector,
		match = !seed && tokenize( ( selector = compiled.selector || selector ) );

	results = results || [];

	// Try to minimize operations if there is only one selector in the list and no seed
	// (the latter of which guarantees us context)
	if ( match.length === 1 ) {

		// Reduce context if the leading compound selector is an ID
		tokens = match[ 0 ] = match[ 0 ].slice( 0 );
		if ( tokens.length > 2 && ( token = tokens[ 0 ] ).type === "ID" &&
			context.nodeType === 9 && documentIsHTML && Expr.relative[ tokens[ 1 ].type ] ) {

			context = ( Expr.find[ "ID" ]( token.matches[ 0 ]
				.replace( runescape, funescape ), context ) || [] )[ 0 ];
			if ( !context ) {
				return results;

			// Precompiled matchers will still verify ancestry, so step up a level
			} else if ( compiled ) {
				context = context.parentNode;
			}

			selector = selector.slice( tokens.shift().value.length );
		}

		// Fetch a seed set for right-to-left matching
		i = matchExpr[ "needsContext" ].test( selector ) ? 0 : tokens.length;
		while ( i-- ) {
			token = tokens[ i ];

			// Abort if we hit a combinator
			if ( Expr.relative[ ( type = token.type ) ] ) {
				break;
			}
			if ( ( find = Expr.find[ type ] ) ) {

				// Search, expanding context for leading sibling combinators
				if ( ( seed = find(
					token.matches[ 0 ].replace( runescape, funescape ),
					rsibling.test( tokens[ 0 ].type ) && testContext( context.parentNode ) ||
						context
				) ) ) {

					// If seed is empty or no tokens remain, we can return early
					tokens.splice( i, 1 );
					selector = seed.length && toSelector( tokens );
					if ( !selector ) {
						push.apply( results, seed );
						return results;
					}

					break;
				}
			}
		}
	}

	// Compile and execute a filtering function if one is not provided
	// Provide `match` to avoid retokenization if we modified the selector above
	( compiled || compile( selector, match ) )(
		seed,
		context,
		!documentIsHTML,
		results,
		!context || rsibling.test( selector ) && testContext( context.parentNode ) || context
	);
	return results;
};

// One-time assignments

// Sort stability
support.sortStable = expando.split( "" ).sort( sortOrder ).join( "" ) === expando;

// Support: Chrome 14-35+
// Always assume duplicates if they aren't passed to the comparison function
support.detectDuplicates = !!hasDuplicate;

// Initialize against the default document
setDocument();

// Support: Webkit<537.32 - Safari 6.0.3/Chrome 25 (fixed in Chrome 27)
// Detached nodes confoundingly follow *each other*
support.sortDetached = assert( function( el ) {

	// Should return 1, but returns 4 (following)
	return el.compareDocumentPosition( document.createElement( "fieldset" ) ) & 1;
} );

// Support: IE<8
// Prevent attribute/property "interpolation"
// https://msdn.microsoft.com/en-us/library/ms536429%28VS.85%29.aspx
if ( !assert( function( el ) {
	el.innerHTML = "<a href='#'></a>";
	return el.firstChild.getAttribute( "href" ) === "#";
} ) ) {
	addHandle( "type|href|height|width", function( elem, name, isXML ) {
		if ( !isXML ) {
			return elem.getAttribute( name, name.toLowerCase() === "type" ? 1 : 2 );
		}
	} );
}

// Support: IE<9
// Use defaultValue in place of getAttribute("value")
if ( !support.attributes || !assert( function( el ) {
	el.innerHTML = "<input/>";
	el.firstChild.setAttribute( "value", "" );
	return el.firstChild.getAttribute( "value" ) === "";
} ) ) {
	addHandle( "value", function( elem, _name, isXML ) {
		if ( !isXML && elem.nodeName.toLowerCase() === "input" ) {
			return elem.defaultValue;
		}
	} );
}

// Support: IE<9
// Use getAttributeNode to fetch booleans when getAttribute lies
if ( !assert( function( el ) {
	return el.getAttribute( "disabled" ) == null;
} ) ) {
	addHandle( booleans, function( elem, name, isXML ) {
		var val;
		if ( !isXML ) {
			return elem[ name ] === true ? name.toLowerCase() :
				( val = elem.getAttributeNode( name ) ) && val.specified ?
					val.value :
					null;
		}
	} );
}

return Sizzle;

} )( window );



jQuery.find = Sizzle;
jQuery.expr = Sizzle.selectors;

// Deprecated
jQuery.expr[ ":" ] = jQuery.expr.pseudos;
jQuery.uniqueSort = jQuery.unique = Sizzle.uniqueSort;
jQuery.text = Sizzle.getText;
jQuery.isXMLDoc = Sizzle.isXML;
jQuery.contains = Sizzle.contains;
jQuery.escapeSelector = Sizzle.escape;




var dir = function( elem, dir, until ) {
	var matched = [],
		truncate = until !== undefined;

	while ( ( elem = elem[ dir ] ) && elem.nodeType !== 9 ) {
		if ( elem.nodeType === 1 ) {
			if ( truncate && jQuery( elem ).is( until ) ) {
				break;
			}
			matched.push( elem );
		}
	}
	return matched;
};


var siblings = function( n, elem ) {
	var matched = [];

	for ( ; n; n = n.nextSibling ) {
		if ( n.nodeType === 1 && n !== elem ) {
			matched.push( n );
		}
	}

	return matched;
};


var rneedsContext = jQuery.expr.match.needsContext;



function nodeName( elem, name ) {

  return elem.nodeName && elem.nodeName.toLowerCase() === name.toLowerCase();

};
var rsingleTag = ( /^<([a-z][^\/\0>:\x20\t\r\n\f]*)[\x20\t\r\n\f]*\/?>(?:<\/\1>|)$/i );



// Implement the identical functionality for filter and not
function winnow( elements, qualifier, not ) {
	if ( isFunction( qualifier ) ) {
		return jQuery.grep( elements, function( elem, i ) {
			return !!qualifier.call( elem, i, elem ) !== not;
		} );
	}

	// Single element
	if ( qualifier.nodeType ) {
		return jQuery.grep( elements, function( elem ) {
			return ( elem === qualifier ) !== not;
		} );
	}

	// Arraylike of elements (jQuery, arguments, Array)
	if ( typeof qualifier !== "string" ) {
		return jQuery.grep( elements, function( elem ) {
			return ( indexOf.call( qualifier, elem ) > -1 ) !== not;
		} );
	}

	// Filtered directly for both simple and complex selectors
	return jQuery.filter( qualifier, elements, not );
}

jQuery.filter = function( expr, elems, not ) {
	var elem = elems[ 0 ];

	if ( not ) {
		expr = ":not(" + expr + ")";
	}

	if ( elems.length === 1 && elem.nodeType === 1 ) {
		return jQuery.find.matchesSelector( elem, expr ) ? [ elem ] : [];
	}

	return jQuery.find.matches( expr, jQuery.grep( elems, function( elem ) {
		return elem.nodeType === 1;
	} ) );
};

jQuery.fn.extend( {
	find: function( selector ) {
		var i, ret,
			len = this.length,
			self = this;

		if ( typeof selector !== "string" ) {
			return this.pushStack( jQuery( selector ).filter( function() {
				for ( i = 0; i < len; i++ ) {
					if ( jQuery.contains( self[ i ], this ) ) {
						return true;
					}
				}
			} ) );
		}

		ret = this.pushStack( [] );

		for ( i = 0; i < len; i++ ) {
			jQuery.find( selector, self[ i ], ret );
		}

		return len > 1 ? jQuery.uniqueSort( ret ) : ret;
	},
	filter: function( selector ) {
		return this.pushStack( winnow( this, selector || [], false ) );
	},
	not: function( selector ) {
		return this.pushStack( winnow( this, selector || [], true ) );
	},
	is: function( selector ) {
		return !!winnow(
			this,

			// If this is a positional/relative selector, check membership in the returned set
			// so $("p:first").is("p:last") won't return true for a doc with two "p".
			typeof selector === "string" && rneedsContext.test( selector ) ?
				jQuery( selector ) :
				selector || [],
			false
		).length;
	}
} );


// Initialize a jQuery object


// A central reference to the root jQuery(document)
var rootjQuery,

	// A simple way to check for HTML strings
	// Prioritize #id over <tag> to avoid XSS via location.hash (#9521)
	// Strict HTML recognition (#11290: must start with <)
	// Shortcut simple #id case for speed
	rquickExpr = /^(?:\s*(<[\w\W]+>)[^>]*|#([\w-]+))$/,

	init = jQuery.fn.init = function( selector, context, root ) {
		var match, elem;

		// HANDLE: $(""), $(null), $(undefined), $(false)
		if ( !selector ) {
			return this;
		}

		// Method init() accepts an alternate rootjQuery
		// so migrate can support jQuery.sub (gh-2101)
		root = root || rootjQuery;

		// Handle HTML strings
		if ( typeof selector === "string" ) {
			if ( selector[ 0 ] === "<" &&
				selector[ selector.length - 1 ] === ">" &&
				selector.length >= 3 ) {

				// Assume that strings that start and end with <> are HTML and skip the regex check
				match = [ null, selector, null ];

			} else {
				match = rquickExpr.exec( selector );
			}

			// Match html or make sure no context is specified for #id
			if ( match && ( match[ 1 ] || !context ) ) {

				// HANDLE: $(html) -> $(array)
				if ( match[ 1 ] ) {
					context = context instanceof jQuery ? context[ 0 ] : context;

					// Option to run scripts is true for back-compat
					// Intentionally let the error be thrown if parseHTML is not present
					jQuery.merge( this, jQuery.parseHTML(
						match[ 1 ],
						context && context.nodeType ? context.ownerDocument || context : document,
						true
					) );

					// HANDLE: $(html, props)
					if ( rsingleTag.test( match[ 1 ] ) && jQuery.isPlainObject( context ) ) {
						for ( match in context ) {

							// Properties of context are called as methods if possible
							if ( isFunction( this[ match ] ) ) {
								this[ match ]( context[ match ] );

							// ...and otherwise set as attributes
							} else {
								this.attr( match, context[ match ] );
							}
						}
					}

					return this;

				// HANDLE: $(#id)
				} else {
					elem = document.getElementById( match[ 2 ] );

					if ( elem ) {

						// Inject the element directly into the jQuery object
						this[ 0 ] = elem;
						this.length = 1;
					}
					return this;
				}

			// HANDLE: $(expr, $(...))
			} else if ( !context || context.jquery ) {
				return ( context || root ).find( selector );

			// HANDLE: $(expr, context)
			// (which is just equivalent to: $(context).find(expr)
			} else {
				return this.constructor( context ).find( selector );
			}

		// HANDLE: $(DOMElement)
		} else if ( selector.nodeType ) {
			this[ 0 ] = selector;
			this.length = 1;
			return this;

		// HANDLE: $(function)
		// Shortcut for document ready
		} else if ( isFunction( selector ) ) {
			return root.ready !== undefined ?
				root.ready( selector ) :

				// Execute immediately if ready is not present
				selector( jQuery );
		}

		return jQuery.makeArray( selector, this );
	};

// Give the init function the jQuery prototype for later instantiation
init.prototype = jQuery.fn;

// Initialize central reference
rootjQuery = jQuery( document );


var rparentsprev = /^(?:parents|prev(?:Until|All))/,

	// Methods guaranteed to produce a unique set when starting from a unique set
	guaranteedUnique = {
		children: true,
		contents: true,
		next: true,
		prev: true
	};

jQuery.fn.extend( {
	has: function( target ) {
		var targets = jQuery( target, this ),
			l = targets.length;

		return this.filter( function() {
			var i = 0;
			for ( ; i < l; i++ ) {
				if ( jQuery.contains( this, targets[ i ] ) ) {
					return true;
				}
			}
		} );
	},

	closest: function( selectors, context ) {
		var cur,
			i = 0,
			l = this.length,
			matched = [],
			targets = typeof selectors !== "string" && jQuery( selectors );

		// Positional selectors never match, since there's no _selection_ context
		if ( !rneedsContext.test( selectors ) ) {
			for ( ; i < l; i++ ) {
				for ( cur = this[ i ]; cur && cur !== context; cur = cur.parentNode ) {

					// Always skip document fragments
					if ( cur.nodeType < 11 && ( targets ?
						targets.index( cur ) > -1 :

						// Don't pass non-elements to Sizzle
						cur.nodeType === 1 &&
							jQuery.find.matchesSelector( cur, selectors ) ) ) {

						matched.push( cur );
						break;
					}
				}
			}
		}

		return this.pushStack( matched.length > 1 ? jQuery.uniqueSort( matched ) : matched );
	},

	// Determine the position of an element within the set
	index: function( elem ) {

		// No argument, return index in parent
		if ( !elem ) {
			return ( this[ 0 ] && this[ 0 ].parentNode ) ? this.first().prevAll().length : -1;
		}

		// Index in selector
		if ( typeof elem === "string" ) {
			return indexOf.call( jQuery( elem ), this[ 0 ] );
		}

		// Locate the position of the desired element
		return indexOf.call( this,

			// If it receives a jQuery object, the first element is used
			elem.jquery ? elem[ 0 ] : elem
		);
	},

	add: function( selector, context ) {
		return this.pushStack(
			jQuery.uniqueSort(
				jQuery.merge( this.get(), jQuery( selector, context ) )
			)
		);
	},

	addBack: function( selector ) {
		return this.add( selector == null ?
			this.prevObject : this.prevObject.filter( selector )
		);
	}
} );

function sibling( cur, dir ) {
	while ( ( cur = cur[ dir ] ) && cur.nodeType !== 1 ) {}
	return cur;
}

jQuery.each( {
	parent: function( elem ) {
		var parent = elem.parentNode;
		return parent && parent.nodeType !== 11 ? parent : null;
	},
	parents: function( elem ) {
		return dir( elem, "parentNode" );
	},
	parentsUntil: function( elem, _i, until ) {
		return dir( elem, "parentNode", until );
	},
	next: function( elem ) {
		return sibling( elem, "nextSibling" );
	},
	prev: function( elem ) {
		return sibling( elem, "previousSibling" );
	},
	nextAll: function( elem ) {
		return dir( elem, "nextSibling" );
	},
	prevAll: function( elem ) {
		return dir( elem, "previousSibling" );
	},
	nextUntil: function( elem, _i, until ) {
		return dir( elem, "nextSibling", until );
	},
	prevUntil: function( elem, _i, until ) {
		return dir( elem, "previousSibling", until );
	},
	siblings: function( elem ) {
		return siblings( ( elem.parentNode || {} ).firstChild, elem );
	},
	children: function( elem ) {
		return siblings( elem.firstChild );
	},
	contents: function( elem ) {
		if ( elem.contentDocument != null &&

			// Support: IE 11+
			// <object> elements with no `data` attribute has an object
			// `contentDocument` with a `null` prototype.
			getProto( elem.contentDocument ) ) {

			return elem.contentDocument;
		}

		// Support: IE 9 - 11 only, iOS 7 only, Android Browser <=4.3 only
		// Treat the template element as a regular one in browsers that
		// don't support it.
		if ( nodeName( elem, "template" ) ) {
			elem = elem.content || elem;
		}

		return jQuery.merge( [], elem.childNodes );
	}
}, function( name, fn ) {
	jQuery.fn[ name ] = function( until, selector ) {
		var matched = jQuery.map( this, fn, until );

		if ( name.slice( -5 ) !== "Until" ) {
			selector = until;
		}

		if ( selector && typeof selector === "string" ) {
			matched = jQuery.filter( selector, matched );
		}

		if ( this.length > 1 ) {

			// Remove duplicates
			if ( !guaranteedUnique[ name ] ) {
				jQuery.uniqueSort( matched );
			}

			// Reverse order for parents* and prev-derivatives
			if ( rparentsprev.test( name ) ) {
				matched.reverse();
			}
		}

		return this.pushStack( matched );
	};
} );
var rnothtmlwhite = ( /[^\x20\t\r\n\f]+/g );



// Convert String-formatted options into Object-formatted ones
function createOptions( options ) {
	var object = {};
	jQuery.each( options.match( rnothtmlwhite ) || [], function( _, flag ) {
		object[ flag ] = true;
	} );
	return object;
}

/*
 * Create a callback list using the following parameters:
 *
 *	options: an optional list of space-separated options that will change how
 *			the callback list behaves or a more traditional option object
 *
 * By default a callback list will act like an event callback list and can be
 * "fired" multiple times.
 *
 * Possible options:
 *
 *	once:			will ensure the callback list can only be fired once (like a Deferred)
 *
 *	memory:			will keep track of previous values and will call any callback added
 *					after the list has been fired right away with the latest "memorized"
 *					values (like a Deferred)
 *
 *	unique:			will ensure a callback can only be added once (no duplicate in the list)
 *
 *	stopOnFalse:	interrupt callings when a callback returns false
 *
 */
jQuery.Callbacks = function( options ) {

	// Convert options from String-formatted to Object-formatted if needed
	// (we check in cache first)
	options = typeof options === "string" ?
		createOptions( options ) :
		jQuery.extend( {}, options );

	var // Flag to know if list is currently firing
		firing,

		// Last fire value for non-forgettable lists
		memory,

		// Flag to know if list was already fired
		fired,

		// Flag to prevent firing
		locked,

		// Actual callback list
		list = [],

		// Queue of execution data for repeatable lists
		queue = [],

		// Index of currently firing callback (modified by add/remove as needed)
		firingIndex = -1,

		// Fire callbacks
		fire = function() {

			// Enforce single-firing
			locked = locked || options.once;

			// Execute callbacks for all pending executions,
			// respecting firingIndex overrides and runtime changes
			fired = firing = true;
			for ( ; queue.length; firingIndex = -1 ) {
				memory = queue.shift();
				while ( ++firingIndex < list.length ) {

					// Run callback and check for early termination
					if ( list[ firingIndex ].apply( memory[ 0 ], memory[ 1 ] ) === false &&
						options.stopOnFalse ) {

						// Jump to end and forget the data so .add doesn't re-fire
						firingIndex = list.length;
						memory = false;
					}
				}
			}

			// Forget the data if we're done with it
			if ( !options.memory ) {
				memory = false;
			}

			firing = false;

			// Clean up if we're done firing for good
			if ( locked ) {

				// Keep an empty list if we have data for future add calls
				if ( memory ) {
					list = [];

				// Otherwise, this object is spent
				} else {
					list = "";
				}
			}
		},

		// Actual Callbacks object
		self = {

			// Add a callback or a collection of callbacks to the list
			add: function() {
				if ( list ) {

					// If we have memory from a past run, we should fire after adding
					if ( memory && !firing ) {
						firingIndex = list.length - 1;
						queue.push( memory );
					}

					( function add( args ) {
						jQuery.each( args, function( _, arg ) {
							if ( isFunction( arg ) ) {
								if ( !options.unique || !self.has( arg ) ) {
									list.push( arg );
								}
							} else if ( arg && arg.length && toType( arg ) !== "string" ) {

								// Inspect recursively
								add( arg );
							}
						} );
					} )( arguments );

					if ( memory && !firing ) {
						fire();
					}
				}
				return this;
			},

			// Remove a callback from the list
			remove: function() {
				jQuery.each( arguments, function( _, arg ) {
					var index;
					while ( ( index = jQuery.inArray( arg, list, index ) ) > -1 ) {
						list.splice( index, 1 );

						// Handle firing indexes
						if ( index <= firingIndex ) {
							firingIndex--;
						}
					}
				} );
				return this;
			},

			// Check if a given callback is in the list.
			// If no argument is given, return whether or not list has callbacks attached.
			has: function( fn ) {
				return fn ?
					jQuery.inArray( fn, list ) > -1 :
					list.length > 0;
			},

			// Remove all callbacks from the list
			empty: function() {
				if ( list ) {
					list = [];
				}
				return this;
			},

			// Disable .fire and .add
			// Abort any current/pending executions
			// Clear all callbacks and values
			disable: function() {
				locked = queue = [];
				list = memory = "";
				return this;
			},
			disabled: function() {
				return !list;
			},

			// Disable .fire
			// Also disable .add unless we have memory (since it would have no effect)
			// Abort any pending executions
			lock: function() {
				locked = queue = [];
				if ( !memory && !firing ) {
					list = memory = "";
				}
				return this;
			},
			locked: function() {
				return !!locked;
			},

			// Call all callbacks with the given context and arguments
			fireWith: function( context, args ) {
				if ( !locked ) {
					args = args || [];
					args = [ context, args.slice ? args.slice() : args ];
					queue.push( args );
					if ( !firing ) {
						fire();
					}
				}
				return this;
			},

			// Call all the callbacks with the given arguments
			fire: function() {
				self.fireWith( this, arguments );
				return this;
			},

			// To know if the callbacks have already been called at least once
			fired: function() {
				return !!fired;
			}
		};

	return self;
};


function Identity( v ) {
	return v;
}
function Thrower( ex ) {
	throw ex;
}

function adoptValue( value, resolve, reject, noValue ) {
	var method;

	try {

		// Check for promise aspect first to privilege synchronous behavior
		if ( value && isFunction( ( method = value.promise ) ) ) {
			method.call( value ).done( resolve ).fail( reject );

		// Other thenables
		} else if ( value && isFunction( ( method = value.then ) ) ) {
			method.call( value, resolve, reject );

		// Other non-thenables
		} else {

			// Control `resolve` arguments by letting Array#slice cast boolean `noValue` to integer:
			// * false: [ value ].slice( 0 ) => resolve( value )
			// * true: [ value ].slice( 1 ) => resolve()
			resolve.apply( undefined, [ value ].slice( noValue ) );
		}

	// For Promises/A+, convert exceptions into rejections
	// Since jQuery.when doesn't unwrap thenables, we can skip the extra checks appearing in
	// Deferred#then to conditionally suppress rejection.
	} catch ( value ) {

		// Support: Android 4.0 only
		// Strict mode functions invoked without .call/.apply get global-object context
		reject.apply( undefined, [ value ] );
	}
}

jQuery.extend( {

	Deferred: function( func ) {
		var tuples = [

				// action, add listener, callbacks,
				// ... .then handlers, argument index, [final state]
				[ "notify", "progress", jQuery.Callbacks( "memory" ),
					jQuery.Callbacks( "memory" ), 2 ],
				[ "resolve", "done", jQuery.Callbacks( "once memory" ),
					jQuery.Callbacks( "once memory" ), 0, "resolved" ],
				[ "reject", "fail", jQuery.Callbacks( "once memory" ),
					jQuery.Callbacks( "once memory" ), 1, "rejected" ]
			],
			state = "pending",
			promise = {
				state: function() {
					return state;
				},
				always: function() {
					deferred.done( arguments ).fail( arguments );
					return this;
				},
				"catch": function( fn ) {
					return promise.then( null, fn );
				},

				// Keep pipe for back-compat
				pipe: function( /* fnDone, fnFail, fnProgress */ ) {
					var fns = arguments;

					return jQuery.Deferred( function( newDefer ) {
						jQuery.each( tuples, function( _i, tuple ) {

							// Map tuples (progress, done, fail) to arguments (done, fail, progress)
							var fn = isFunction( fns[ tuple[ 4 ] ] ) && fns[ tuple[ 4 ] ];

							// deferred.progress(function() { bind to newDefer or newDefer.notify })
							// deferred.done(function() { bind to newDefer or newDefer.resolve })
							// deferred.fail(function() { bind to newDefer or newDefer.reject })
							deferred[ tuple[ 1 ] ]( function() {
								var returned = fn && fn.apply( this, arguments );
								if ( returned && isFunction( returned.promise ) ) {
									returned.promise()
										.progress( newDefer.notify )
										.done( newDefer.resolve )
										.fail( newDefer.reject );
								} else {
									newDefer[ tuple[ 0 ] + "With" ](
										this,
										fn ? [ returned ] : arguments
									);
								}
							} );
						} );
						fns = null;
					} ).promise();
				},
				then: function( onFulfilled, onRejected, onProgress ) {
					var maxDepth = 0;
					function resolve( depth, deferred, handler, special ) {
						return function() {
							var that = this,
								args = arguments,
								mightThrow = function() {
									var returned, then;

									// Support: Promises/A+ section 2.3.3.3.3
									// https://promisesaplus.com/#point-59
									// Ignore double-resolution attempts
									if ( depth < maxDepth ) {
										return;
									}

									returned = handler.apply( that, args );

									// Support: Promises/A+ section 2.3.1
									// https://promisesaplus.com/#point-48
									if ( returned === deferred.promise() ) {
										throw new TypeError( "Thenable self-resolution" );
									}

									// Support: Promises/A+ sections 2.3.3.1, 3.5
									// https://promisesaplus.com/#point-54
									// https://promisesaplus.com/#point-75
									// Retrieve `then` only once
									then = returned &&

										// Support: Promises/A+ section 2.3.4
										// https://promisesaplus.com/#point-64
										// Only check objects and functions for thenability
										( typeof returned === "object" ||
											typeof returned === "function" ) &&
										returned.then;

									// Handle a returned thenable
									if ( isFunction( then ) ) {

										// Special processors (notify) just wait for resolution
										if ( special ) {
											then.call(
												returned,
												resolve( maxDepth, deferred, Identity, special ),
												resolve( maxDepth, deferred, Thrower, special )
											);

										// Normal processors (resolve) also hook into progress
										} else {

											// ...and disregard older resolution values
											maxDepth++;

											then.call(
												returned,
												resolve( maxDepth, deferred, Identity, special ),
												resolve( maxDepth, deferred, Thrower, special ),
												resolve( maxDepth, deferred, Identity,
													deferred.notifyWith )
											);
										}

									// Handle all other returned values
									} else {

										// Only substitute handlers pass on context
										// and multiple values (non-spec behavior)
										if ( handler !== Identity ) {
											that = undefined;
											args = [ returned ];
										}

										// Process the value(s)
										// Default process is resolve
										( special || deferred.resolveWith )( that, args );
									}
								},

								// Only normal processors (resolve) catch and reject exceptions
								process = special ?
									mightThrow :
									function() {
										try {
											mightThrow();
										} catch ( e ) {

											if ( jQuery.Deferred.exceptionHook ) {
												jQuery.Deferred.exceptionHook( e,
													process.stackTrace );
											}

											// Support: Promises/A+ section 2.3.3.3.4.1
											// https://promisesaplus.com/#point-61
											// Ignore post-resolution exceptions
											if ( depth + 1 >= maxDepth ) {

												// Only substitute handlers pass on context
												// and multiple values (non-spec behavior)
												if ( handler !== Thrower ) {
													that = undefined;
													args = [ e ];
												}

												deferred.rejectWith( that, args );
											}
										}
									};

							// Support: Promises/A+ section 2.3.3.3.1
							// https://promisesaplus.com/#point-57
							// Re-resolve promises immediately to dodge false rejection from
							// subsequent errors
							if ( depth ) {
								process();
							} else {

								// Call an optional hook to record the stack, in case of exception
								// since it's otherwise lost when execution goes async
								if ( jQuery.Deferred.getStackHook ) {
									process.stackTrace = jQuery.Deferred.getStackHook();
								}
								window.setTimeout( process );
							}
						};
					}

					return jQuery.Deferred( function( newDefer ) {

						// progress_handlers.add( ... )
						tuples[ 0 ][ 3 ].add(
							resolve(
								0,
								newDefer,
								isFunction( onProgress ) ?
									onProgress :
									Identity,
								newDefer.notifyWith
							)
						);

						// fulfilled_handlers.add( ... )
						tuples[ 1 ][ 3 ].add(
							resolve(
								0,
								newDefer,
								isFunction( onFulfilled ) ?
									onFulfilled :
									Identity
							)
						);

						// rejected_handlers.add( ... )
						tuples[ 2 ][ 3 ].add(
							resolve(
								0,
								newDefer,
								isFunction( onRejected ) ?
									onRejected :
									Thrower
							)
						);
					} ).promise();
				},

				// Get a promise for this deferred
				// If obj is provided, the promise aspect is added to the object
				promise: function( obj ) {
					return obj != null ? jQuery.extend( obj, promise ) : promise;
				}
			},
			deferred = {};

		// Add list-specific methods
		jQuery.each( tuples, function( i, tuple ) {
			var list = tuple[ 2 ],
				stateString = tuple[ 5 ];

			// promise.progress = list.add
			// promise.done = list.add
			// promise.fail = list.add
			promise[ tuple[ 1 ] ] = list.add;

			// Handle state
			if ( stateString ) {
				list.add(
					function() {

						// state = "resolved" (i.e., fulfilled)
						// state = "rejected"
						state = stateString;
					},

					// rejected_callbacks.disable
					// fulfilled_callbacks.disable
					tuples[ 3 - i ][ 2 ].disable,

					// rejected_handlers.disable
					// fulfilled_handlers.disable
					tuples[ 3 - i ][ 3 ].disable,

					// progress_callbacks.lock
					tuples[ 0 ][ 2 ].lock,

					// progress_handlers.lock
					tuples[ 0 ][ 3 ].lock
				);
			}

			// progress_handlers.fire
			// fulfilled_handlers.fire
			// rejected_handlers.fire
			list.add( tuple[ 3 ].fire );

			// deferred.notify = function() { deferred.notifyWith(...) }
			// deferred.resolve = function() { deferred.resolveWith(...) }
			// deferred.reject = function() { deferred.rejectWith(...) }
			deferred[ tuple[ 0 ] ] = function() {
				deferred[ tuple[ 0 ] + "With" ]( this === deferred ? undefined : this, arguments );
				return this;
			};

			// deferred.notifyWith = list.fireWith
			// deferred.resolveWith = list.fireWith
			// deferred.rejectWith = list.fireWith
			deferred[ tuple[ 0 ] + "With" ] = list.fireWith;
		} );

		// Make the deferred a promise
		promise.promise( deferred );

		// Call given func if any
		if ( func ) {
			func.call( deferred, deferred );
		}

		// All done!
		return deferred;
	},

	// Deferred helper
	when: function( singleValue ) {
		var

			// count of uncompleted subordinates
			remaining = arguments.length,

			// count of unprocessed arguments
			i = remaining,

			// subordinate fulfillment data
			resolveContexts = Array( i ),
			resolveValues = slice.call( arguments ),

			// the master Deferred
			master = jQuery.Deferred(),

			// subordinate callback factory
			updateFunc = function( i ) {
				return function( value ) {
					resolveContexts[ i ] = this;
					resolveValues[ i ] = arguments.length > 1 ? slice.call( arguments ) : value;
					if ( !( --remaining ) ) {
						master.resolveWith( resolveContexts, resolveValues );
					}
				};
			};

		// Single- and empty arguments are adopted like Promise.resolve
		if ( remaining <= 1 ) {
			adoptValue( singleValue, master.done( updateFunc( i ) ).resolve, master.reject,
				!remaining );

			// Use .then() to unwrap secondary thenables (cf. gh-3000)
			if ( master.state() === "pending" ||
				isFunction( resolveValues[ i ] && resolveValues[ i ].then ) ) {

				return master.then();
			}
		}

		// Multiple arguments are aggregated like Promise.all array elements
		while ( i-- ) {
			adoptValue( resolveValues[ i ], updateFunc( i ), master.reject );
		}

		return master.promise();
	}
} );


// These usually indicate a programmer mistake during development,
// warn about them ASAP rather than swallowing them by default.
var rerrorNames = /^(Eval|Internal|Range|Reference|Syntax|Type|URI)Error$/;

jQuery.Deferred.exceptionHook = function( error, stack ) {

	// Support: IE 8 - 9 only
	// Console exists when dev tools are open, which can happen at any time
	if ( window.console && window.console.warn && error && rerrorNames.test( error.name ) ) {
		window.console.warn( "jQuery.Deferred exception: " + error.message, error.stack, stack );
	}
};




jQuery.readyException = function( error ) {
	window.setTimeout( function() {
		throw error;
	} );
};




// The deferred used on DOM ready
var readyList = jQuery.Deferred();

jQuery.fn.ready = function( fn ) {

	readyList
		.then( fn )

		// Wrap jQuery.readyException in a function so that the lookup
		// happens at the time of error handling instead of callback
		// registration.
		.catch( function( error ) {
			jQuery.readyException( error );
		} );

	return this;
};

jQuery.extend( {

	// Is the DOM ready to be used? Set to true once it occurs.
	isReady: false,

	// A counter to track how many items to wait for before
	// the ready event fires. See #6781
	readyWait: 1,

	// Handle when the DOM is ready
	ready: function( wait ) {

		// Abort if there are pending holds or we're already ready
		if ( wait === true ? --jQuery.readyWait : jQuery.isReady ) {
			return;
		}

		// Remember that the DOM is ready
		jQuery.isReady = true;

		// If a normal DOM Ready event fired, decrement, and wait if need be
		if ( wait !== true && --jQuery.readyWait > 0 ) {
			return;
		}

		// If there are functions bound, to execute
		readyList.resolveWith( document, [ jQuery ] );
	}
} );

jQuery.ready.then = readyList.then;

// The ready event handler and self cleanup method
function completed() {
	document.removeEventListener( "DOMContentLoaded", completed );
	window.removeEventListener( "load", completed );
	jQuery.ready();
}

// Catch cases where $(document).ready() is called
// after the browser event has already occurred.
// Support: IE <=9 - 10 only
// Older IE sometimes signals "interactive" too soon
if ( document.readyState === "complete" ||
	( document.readyState !== "loading" && !document.documentElement.doScroll ) ) {

	// Handle it asynchronously to allow scripts the opportunity to delay ready
	window.setTimeout( jQuery.ready );

} else {

	// Use the handy event callback
	document.addEventListener( "DOMContentLoaded", completed );

	// A fallback to window.onload, that will always work
	window.addEventListener( "load", completed );
}




// Multifunctional method to get and set values of a collection
// The value/s can optionally be executed if it's a function
var access = function( elems, fn, key, value, chainable, emptyGet, raw ) {
	var i = 0,
		len = elems.length,
		bulk = key == null;

	// Sets many values
	if ( toType( key ) === "object" ) {
		chainable = true;
		for ( i in key ) {
			access( elems, fn, i, key[ i ], true, emptyGet, raw );
		}

	// Sets one value
	} else if ( value !== undefined ) {
		chainable = true;

		if ( !isFunction( value ) ) {
			raw = true;
		}

		if ( bulk ) {

			// Bulk operations run against the entire set
			if ( raw ) {
				fn.call( elems, value );
				fn = null;

			// ...except when executing function values
			} else {
				bulk = fn;
				fn = function( elem, _key, value ) {
					return bulk.call( jQuery( elem ), value );
				};
			}
		}

		if ( fn ) {
			for ( ; i < len; i++ ) {
				fn(
					elems[ i ], key, raw ?
					value :
					value.call( elems[ i ], i, fn( elems[ i ], key ) )
				);
			}
		}
	}

	if ( chainable ) {
		return elems;
	}

	// Gets
	if ( bulk ) {
		return fn.call( elems );
	}

	return len ? fn( elems[ 0 ], key ) : emptyGet;
};


// Matches dashed string for camelizing
var rmsPrefix = /^-ms-/,
	rdashAlpha = /-([a-z])/g;

// Used by camelCase as callback to replace()
function fcamelCase( _all, letter ) {
	return letter.toUpperCase();
}

// Convert dashed to camelCase; used by the css and data modules
// Support: IE <=9 - 11, Edge 12 - 15
// Microsoft forgot to hump their vendor prefix (#9572)
function camelCase( string ) {
	return string.replace( rmsPrefix, "ms-" ).replace( rdashAlpha, fcamelCase );
}
var acceptData = function( owner ) {

	// Accepts only:
	//  - Node
	//    - Node.ELEMENT_NODE
	//    - Node.DOCUMENT_NODE
	//  - Object
	//    - Any
	return owner.nodeType === 1 || owner.nodeType === 9 || !( +owner.nodeType );
};




function Data() {
	this.expando = jQuery.expando + Data.uid++;
}

Data.uid = 1;

Data.prototype = {

	cache: function( owner ) {

		// Check if the owner object already has a cache
		var value = owner[ this.expando ];

		// If not, create one
		if ( !value ) {
			value = {};

			// We can accept data for non-element nodes in modern browsers,
			// but we should not, see #8335.
			// Always return an empty object.
			if ( acceptData( owner ) ) {

				// If it is a node unlikely to be stringify-ed or looped over
				// use plain assignment
				if ( owner.nodeType ) {
					owner[ this.expando ] = value;

				// Otherwise secure it in a non-enumerable property
				// configurable must be true to allow the property to be
				// deleted when data is removed
				} else {
					Object.defineProperty( owner, this.expando, {
						value: value,
						configurable: true
					} );
				}
			}
		}

		return value;
	},
	set: function( owner, data, value ) {
		var prop,
			cache = this.cache( owner );

		// Handle: [ owner, key, value ] args
		// Always use camelCase key (gh-2257)
		if ( typeof data === "string" ) {
			cache[ camelCase( data ) ] = value;

		// Handle: [ owner, { properties } ] args
		} else {

			// Copy the properties one-by-one to the cache object
			for ( prop in data ) {
				cache[ camelCase( prop ) ] = data[ prop ];
			}
		}
		return cache;
	},
	get: function( owner, key ) {
		return key === undefined ?
			this.cache( owner ) :

			// Always use camelCase key (gh-2257)
			owner[ this.expando ] && owner[ this.expando ][ camelCase( key ) ];
	},
	access: function( owner, key, value ) {

		// In cases where either:
		//
		//   1. No key was specified
		//   2. A string key was specified, but no value provided
		//
		// Take the "read" path and allow the get method to determine
		// which value to return, respectively either:
		//
		//   1. The entire cache object
		//   2. The data stored at the key
		//
		if ( key === undefined ||
				( ( key && typeof key === "string" ) && value === undefined ) ) {

			return this.get( owner, key );
		}

		// When the key is not a string, or both a key and value
		// are specified, set or extend (existing objects) with either:
		//
		//   1. An object of properties
		//   2. A key and value
		//
		this.set( owner, key, value );

		// Since the "set" path can have two possible entry points
		// return the expected data based on which path was taken[*]
		return value !== undefined ? value : key;
	},
	remove: function( owner, key ) {
		var i,
			cache = owner[ this.expando ];

		if ( cache === undefined ) {
			return;
		}

		if ( key !== undefined ) {

			// Support array or space separated string of keys
			if ( Array.isArray( key ) ) {

				// If key is an array of keys...
				// We always set camelCase keys, so remove that.
				key = key.map( camelCase );
			} else {
				key = camelCase( key );

				// If a key with the spaces exists, use it.
				// Otherwise, create an array by matching non-whitespace
				key = key in cache ?
					[ key ] :
					( key.match( rnothtmlwhite ) || [] );
			}

			i = key.length;

			while ( i-- ) {
				delete cache[ key[ i ] ];
			}
		}

		// Remove the expando if there's no more data
		if ( key === undefined || jQuery.isEmptyObject( cache ) ) {

			// Support: Chrome <=35 - 45
			// Webkit & Blink performance suffers when deleting properties
			// from DOM nodes, so set to undefined instead
			// https://bugs.chromium.org/p/chromium/issues/detail?id=378607 (bug restricted)
			if ( owner.nodeType ) {
				owner[ this.expando ] = undefined;
			} else {
				delete owner[ this.expando ];
			}
		}
	},
	hasData: function( owner ) {
		var cache = owner[ this.expando ];
		return cache !== undefined && !jQuery.isEmptyObject( cache );
	}
};
var dataPriv = new Data();

var dataUser = new Data();



//	Implementation Summary
//
//	1. Enforce API surface and semantic compatibility with 1.9.x branch
//	2. Improve the module's maintainability by reducing the storage
//		paths to a single mechanism.
//	3. Use the same single mechanism to support "private" and "user" data.
//	4. _Never_ expose "private" data to user code (TODO: Drop _data, _removeData)
//	5. Avoid exposing implementation details on user objects (eg. expando properties)
//	6. Provide a clear path for implementation upgrade to WeakMap in 2014

var rbrace = /^(?:\{[\w\W]*\}|\[[\w\W]*\])$/,
	rmultiDash = /[A-Z]/g;

function getData( data ) {
	if ( data === "true" ) {
		return true;
	}

	if ( data === "false" ) {
		return false;
	}

	if ( data === "null" ) {
		return null;
	}

	// Only convert to a number if it doesn't change the string
	if ( data === +data + "" ) {
		return +data;
	}

	if ( rbrace.test( data ) ) {
		return JSON.parse( data );
	}

	return data;
}

function dataAttr( elem, key, data ) {
	var name;

	// If nothing was found internally, try to fetch any
	// data from the HTML5 data-* attribute
	if ( data === undefined && elem.nodeType === 1 ) {
		name = "data-" + key.replace( rmultiDash, "-$&" ).toLowerCase();
		data = elem.getAttribute( name );

		if ( typeof data === "string" ) {
			try {
				data = getData( data );
			} catch ( e ) {}

			// Make sure we set the data so it isn't changed later
			dataUser.set( elem, key, data );
		} else {
			data = undefined;
		}
	}
	return data;
}

jQuery.extend( {
	hasData: function( elem ) {
		return dataUser.hasData( elem ) || dataPriv.hasData( elem );
	},

	data: function( elem, name, data ) {
		return dataUser.access( elem, name, data );
	},

	removeData: function( elem, name ) {
		dataUser.remove( elem, name );
	},

	// TODO: Now that all calls to _data and _removeData have been replaced
	// with direct calls to dataPriv methods, these can be deprecated.
	_data: function( elem, name, data ) {
		return dataPriv.access( elem, name, data );
	},

	_removeData: function( elem, name ) {
		dataPriv.remove( elem, name );
	}
} );

jQuery.fn.extend( {
	data: function( key, value ) {
		var i, name, data,
			elem = this[ 0 ],
			attrs = elem && elem.attributes;

		// Gets all values
		if ( key === undefined ) {
			if ( this.length ) {
				data = dataUser.get( elem );

				if ( elem.nodeType === 1 && !dataPriv.get( elem, "hasDataAttrs" ) ) {
					i = attrs.length;
					while ( i-- ) {

						// Support: IE 11 only
						// The attrs elements can be null (#14894)
						if ( attrs[ i ] ) {
							name = attrs[ i ].name;
							if ( name.indexOf( "data-" ) === 0 ) {
								name = camelCase( name.slice( 5 ) );
								dataAttr( elem, name, data[ name ] );
							}
						}
					}
					dataPriv.set( elem, "hasDataAttrs", true );
				}
			}

			return data;
		}

		// Sets multiple values
		if ( typeof key === "object" ) {
			return this.each( function() {
				dataUser.set( this, key );
			} );
		}

		return access( this, function( value ) {
			var data;

			// The calling jQuery object (element matches) is not empty
			// (and therefore has an element appears at this[ 0 ]) and the
			// `value` parameter was not undefined. An empty jQuery object
			// will result in `undefined` for elem = this[ 0 ] which will
			// throw an exception if an attempt to read a data cache is made.
			if ( elem && value === undefined ) {

				// Attempt to get data from the cache
				// The key will always be camelCased in Data
				data = dataUser.get( elem, key );
				if ( data !== undefined ) {
					return data;
				}

				// Attempt to "discover" the data in
				// HTML5 custom data-* attrs
				data = dataAttr( elem, key );
				if ( data !== undefined ) {
					return data;
				}

				// We tried really hard, but the data doesn't exist.
				return;
			}

			// Set the data...
			this.each( function() {

				// We always store the camelCased key
				dataUser.set( this, key, value );
			} );
		}, null, value, arguments.length > 1, null, true );
	},

	removeData: function( key ) {
		return this.each( function() {
			dataUser.remove( this, key );
		} );
	}
} );


jQuery.extend( {
	queue: function( elem, type, data ) {
		var queue;

		if ( elem ) {
			type = ( type || "fx" ) + "queue";
			queue = dataPriv.get( elem, type );

			// Speed up dequeue by getting out quickly if this is just a lookup
			if ( data ) {
				if ( !queue || Array.isArray( data ) ) {
					queue = dataPriv.access( elem, type, jQuery.makeArray( data ) );
				} else {
					queue.push( data );
				}
			}
			return queue || [];
		}
	},

	dequeue: function( elem, type ) {
		type = type || "fx";

		var queue = jQuery.queue( elem, type ),
			startLength = queue.length,
			fn = queue.shift(),
			hooks = jQuery._queueHooks( elem, type ),
			next = function() {
				jQuery.dequeue( elem, type );
			};

		// If the fx queue is dequeued, always remove the progress sentinel
		if ( fn === "inprogress" ) {
			fn = queue.shift();
			startLength--;
		}

		if ( fn ) {

			// Add a progress sentinel to prevent the fx queue from being
			// automatically dequeued
			if ( type === "fx" ) {
				queue.unshift( "inprogress" );
			}

			// Clear up the last queue stop function
			delete hooks.stop;
			fn.call( elem, next, hooks );
		}

		if ( !startLength && hooks ) {
			hooks.empty.fire();
		}
	},

	// Not public - generate a queueHooks object, or return the current one
	_queueHooks: function( elem, type ) {
		var key = type + "queueHooks";
		return dataPriv.get( elem, key ) || dataPriv.access( elem, key, {
			empty: jQuery.Callbacks( "once memory" ).add( function() {
				dataPriv.remove( elem, [ type + "queue", key ] );
			} )
		} );
	}
} );

jQuery.fn.extend( {
	queue: function( type, data ) {
		var setter = 2;

		if ( typeof type !== "string" ) {
			data = type;
			type = "fx";
			setter--;
		}

		if ( arguments.length < setter ) {
			return jQuery.queue( this[ 0 ], type );
		}

		return data === undefined ?
			this :
			this.each( function() {
				var queue = jQuery.queue( this, type, data );

				// Ensure a hooks for this queue
				jQuery._queueHooks( this, type );

				if ( type === "fx" && queue[ 0 ] !== "inprogress" ) {
					jQuery.dequeue( this, type );
				}
			} );
	},
	dequeue: function( type ) {
		return this.each( function() {
			jQuery.dequeue( this, type );
		} );
	},
	clearQueue: function( type ) {
		return this.queue( type || "fx", [] );
	},

	// Get a promise resolved when queues of a certain type
	// are emptied (fx is the type by default)
	promise: function( type, obj ) {
		var tmp,
			count = 1,
			defer = jQuery.Deferred(),
			elements = this,
			i = this.length,
			resolve = function() {
				if ( !( --count ) ) {
					defer.resolveWith( elements, [ elements ] );
				}
			};

		if ( typeof type !== "string" ) {
			obj = type;
			type = undefined;
		}
		type = type || "fx";

		while ( i-- ) {
			tmp = dataPriv.get( elements[ i ], type + "queueHooks" );
			if ( tmp && tmp.empty ) {
				count++;
				tmp.empty.add( resolve );
			}
		}
		resolve();
		return defer.promise( obj );
	}
} );
var pnum = ( /[+-]?(?:\d*\.|)\d+(?:[eE][+-]?\d+|)/ ).source;

var rcssNum = new RegExp( "^(?:([+-])=|)(" + pnum + ")([a-z%]*)$", "i" );


var cssExpand = [ "Top", "Right", "Bottom", "Left" ];

var documentElement = document.documentElement;



	var isAttached = function( elem ) {
			return jQuery.contains( elem.ownerDocument, elem );
		},
		composed = { composed: true };

	// Support: IE 9 - 11+, Edge 12 - 18+, iOS 10.0 - 10.2 only
	// Check attachment across shadow DOM boundaries when possible (gh-3504)
	// Support: iOS 10.0-10.2 only
	// Early iOS 10 versions support `attachShadow` but not `getRootNode`,
	// leading to errors. We need to check for `getRootNode`.
	if ( documentElement.getRootNode ) {
		isAttached = function( elem ) {
			return jQuery.contains( elem.ownerDocument, elem ) ||
				elem.getRootNode( composed ) === elem.ownerDocument;
		};
	}
var isHiddenWithinTree = function( elem, el ) {

		// isHiddenWithinTree might be called from jQuery#filter function;
		// in that case, element will be second argument
		elem = el || elem;

		// Inline style trumps all
		return elem.style.display === "none" ||
			elem.style.display === "" &&

			// Otherwise, check computed style
			// Support: Firefox <=43 - 45
			// Disconnected elements can have computed display: none, so first confirm that elem is
			// in the document.
			isAttached( elem ) &&

			jQuery.css( elem, "display" ) === "none";
	};



function adjustCSS( elem, prop, valueParts, tween ) {
	var adjusted, scale,
		maxIterations = 20,
		currentValue = tween ?
			function() {
				return tween.cur();
			} :
			function() {
				return jQuery.css( elem, prop, "" );
			},
		initial = currentValue(),
		unit = valueParts && valueParts[ 3 ] || ( jQuery.cssNumber[ prop ] ? "" : "px" ),

		// Starting value computation is required for potential unit mismatches
		initialInUnit = elem.nodeType &&
			( jQuery.cssNumber[ prop ] || unit !== "px" && +initial ) &&
			rcssNum.exec( jQuery.css( elem, prop ) );

	if ( initialInUnit && initialInUnit[ 3 ] !== unit ) {

		// Support: Firefox <=54
		// Halve the iteration target value to prevent interference from CSS upper bounds (gh-2144)
		initial = initial / 2;

		// Trust units reported by jQuery.css
		unit = unit || initialInUnit[ 3 ];

		// Iteratively approximate from a nonzero starting point
		initialInUnit = +initial || 1;

		while ( maxIterations-- ) {

			// Evaluate and update our best guess (doubling guesses that zero out).
			// Finish if the scale equals or crosses 1 (making the old*new product non-positive).
			jQuery.style( elem, prop, initialInUnit + unit );
			if ( ( 1 - scale ) * ( 1 - ( scale = currentValue() / initial || 0.5 ) ) <= 0 ) {
				maxIterations = 0;
			}
			initialInUnit = initialInUnit / scale;

		}

		initialInUnit = initialInUnit * 2;
		jQuery.style( elem, prop, initialInUnit + unit );

		// Make sure we update the tween properties later on
		valueParts = valueParts || [];
	}

	if ( valueParts ) {
		initialInUnit = +initialInUnit || +initial || 0;

		// Apply relative offset (+=/-=) if specified
		adjusted = valueParts[ 1 ] ?
			initialInUnit + ( valueParts[ 1 ] + 1 ) * valueParts[ 2 ] :
			+valueParts[ 2 ];
		if ( tween ) {
			tween.unit = unit;
			tween.start = initialInUnit;
			tween.end = adjusted;
		}
	}
	return adjusted;
}


var defaultDisplayMap = {};

function getDefaultDisplay( elem ) {
	var temp,
		doc = elem.ownerDocument,
		nodeName = elem.nodeName,
		display = defaultDisplayMap[ nodeName ];

	if ( display ) {
		return display;
	}

	temp = doc.body.appendChild( doc.createElement( nodeName ) );
	display = jQuery.css( temp, "display" );

	temp.parentNode.removeChild( temp );

	if ( display === "none" ) {
		display = "block";
	}
	defaultDisplayMap[ nodeName ] = display;

	return display;
}

function showHide( elements, show ) {
	var display, elem,
		values = [],
		index = 0,
		length = elements.length;

	// Determine new display value for elements that need to change
	for ( ; index < length; index++ ) {
		elem = elements[ index ];
		if ( !elem.style ) {
			continue;
		}

		display = elem.style.display;
		if ( show ) {

			// Since we force visibility upon cascade-hidden elements, an immediate (and slow)
			// check is required in this first loop unless we have a nonempty display value (either
			// inline or about-to-be-restored)
			if ( display === "none" ) {
				values[ index ] = dataPriv.get( elem, "display" ) || null;
				if ( !values[ index ] ) {
					elem.style.display = "";
				}
			}
			if ( elem.style.display === "" && isHiddenWithinTree( elem ) ) {
				values[ index ] = getDefaultDisplay( elem );
			}
		} else {
			if ( display !== "none" ) {
				values[ index ] = "none";

				// Remember what we're overwriting
				dataPriv.set( elem, "display", display );
			}
		}
	}

	// Set the display of the elements in a second loop to avoid constant reflow
	for ( index = 0; index < length; index++ ) {
		if ( values[ index ] != null ) {
			elements[ index ].style.display = values[ index ];
		}
	}

	return elements;
}

jQuery.fn.extend( {
	show: function() {
		return showHide( this, true );
	},
	hide: function() {
		return showHide( this );
	},
	toggle: function( state ) {
		if ( typeof state === "boolean" ) {
			return state ? this.show() : this.hide();
		}

		return this.each( function() {
			if ( isHiddenWithinTree( this ) ) {
				jQuery( this ).show();
			} else {
				jQuery( this ).hide();
			}
		} );
	}
} );
var rcheckableType = ( /^(?:checkbox|radio)$/i );

var rtagName = ( /<([a-z][^\/\0>\x20\t\r\n\f]*)/i );

var rscriptType = ( /^$|^module$|\/(?:java|ecma)script/i );



( function() {
	var fragment = document.createDocumentFragment(),
		div = fragment.appendChild( document.createElement( "div" ) ),
		input = document.createElement( "input" );

	// Support: Android 4.0 - 4.3 only
	// Check state lost if the name is set (#11217)
	// Support: Windows Web Apps (WWA)
	// `name` and `type` must use .setAttribute for WWA (#14901)
	input.setAttribute( "type", "radio" );
	input.setAttribute( "checked", "checked" );
	input.setAttribute( "name", "t" );

	div.appendChild( input );

	// Support: Android <=4.1 only
	// Older WebKit doesn't clone checked state correctly in fragments
	support.checkClone = div.cloneNode( true ).cloneNode( true ).lastChild.checked;

	// Support: IE <=11 only
	// Make sure textarea (and checkbox) defaultValue is properly cloned
	div.innerHTML = "<textarea>x</textarea>";
	support.noCloneChecked = !!div.cloneNode( true ).lastChild.defaultValue;

	// Support: IE <=9 only
	// IE <=9 replaces <option> tags with their contents when inserted outside of
	// the select element.
	div.innerHTML = "<option></option>";
	support.option = !!div.lastChild;
} )();


// We have to close these tags to support XHTML (#13200)
var wrapMap = {

	// XHTML parsers do not magically insert elements in the
	// same way that tag soup parsers do. So we cannot shorten
	// this by omitting <tbody> or other required elements.
	thead: [ 1, "<table>", "</table>" ],
	col: [ 2, "<table><colgroup>", "</colgroup></table>" ],
	tr: [ 2, "<table><tbody>", "</tbody></table>" ],
	td: [ 3, "<table><tbody><tr>", "</tr></tbody></table>" ],

	_default: [ 0, "", "" ]
};

wrapMap.tbody = wrapMap.tfoot = wrapMap.colgroup = wrapMap.caption = wrapMap.thead;
wrapMap.th = wrapMap.td;

// Support: IE <=9 only
if ( !support.option ) {
	wrapMap.optgroup = wrapMap.option = [ 1, "<select multiple='multiple'>", "</select>" ];
}


function getAll( context, tag ) {

	// Support: IE <=9 - 11 only
	// Use typeof to avoid zero-argument method invocation on host objects (#15151)
	var ret;

	if ( typeof context.getElementsByTagName !== "undefined" ) {
		ret = context.getElementsByTagName( tag || "*" );

	} else if ( typeof context.querySelectorAll !== "undefined" ) {
		ret = context.querySelectorAll( tag || "*" );

	} else {
		ret = [];
	}

	if ( tag === undefined || tag && nodeName( context, tag ) ) {
		return jQuery.merge( [ context ], ret );
	}

	return ret;
}


// Mark scripts as having already been evaluated
function setGlobalEval( elems, refElements ) {
	var i = 0,
		l = elems.length;

	for ( ; i < l; i++ ) {
		dataPriv.set(
			elems[ i ],
			"globalEval",
			!refElements || dataPriv.get( refElements[ i ], "globalEval" )
		);
	}
}


var rhtml = /<|&#?\w+;/;

function buildFragment( elems, context, scripts, selection, ignored ) {
	var elem, tmp, tag, wrap, attached, j,
		fragment = context.createDocumentFragment(),
		nodes = [],
		i = 0,
		l = elems.length;

	for ( ; i < l; i++ ) {
		elem = elems[ i ];

		if ( elem || elem === 0 ) {

			// Add nodes directly
			if ( toType( elem ) === "object" ) {

				// Support: Android <=4.0 only, PhantomJS 1 only
				// push.apply(_, arraylike) throws on ancient WebKit
				jQuery.merge( nodes, elem.nodeType ? [ elem ] : elem );

			// Convert non-html into a text node
			} else if ( !rhtml.test( elem ) ) {
				nodes.push( context.createTextNode( elem ) );

			// Convert html into DOM nodes
			} else {
				tmp = tmp || fragment.appendChild( context.createElement( "div" ) );

				// Deserialize a standard representation
				tag = ( rtagName.exec( elem ) || [ "", "" ] )[ 1 ].toLowerCase();
				wrap = wrapMap[ tag ] || wrapMap._default;
				tmp.innerHTML = wrap[ 1 ] + jQuery.htmlPrefilter( elem ) + wrap[ 2 ];

				// Descend through wrappers to the right content
				j = wrap[ 0 ];
				while ( j-- ) {
					tmp = tmp.lastChild;
				}

				// Support: Android <=4.0 only, PhantomJS 1 only
				// push.apply(_, arraylike) throws on ancient WebKit
				jQuery.merge( nodes, tmp.childNodes );

				// Remember the top-level container
				tmp = fragment.firstChild;

				// Ensure the created nodes are orphaned (#12392)
				tmp.textContent = "";
			}
		}
	}

	// Remove wrapper from fragment
	fragment.textContent = "";

	i = 0;
	while ( ( elem = nodes[ i++ ] ) ) {

		// Skip elements already in the context collection (trac-4087)
		if ( selection && jQuery.inArray( elem, selection ) > -1 ) {
			if ( ignored ) {
				ignored.push( elem );
			}
			continue;
		}

		attached = isAttached( elem );

		// Append to fragment
		tmp = getAll( fragment.appendChild( elem ), "script" );

		// Preserve script evaluation history
		if ( attached ) {
			setGlobalEval( tmp );
		}

		// Capture executables
		if ( scripts ) {
			j = 0;
			while ( ( elem = tmp[ j++ ] ) ) {
				if ( rscriptType.test( elem.type || "" ) ) {
					scripts.push( elem );
				}
			}
		}
	}

	return fragment;
}


var
	rkeyEvent = /^key/,
	rmouseEvent = /^(?:mouse|pointer|contextmenu|drag|drop)|click/,
	rtypenamespace = /^([^.]*)(?:\.(.+)|)/;

function returnTrue() {
	return true;
}

function returnFalse() {
	return false;
}

// Support: IE <=9 - 11+
// focus() and blur() are asynchronous, except when they are no-op.
// So expect focus to be synchronous when the element is already active,
// and blur to be synchronous when the element is not already active.
// (focus and blur are always synchronous in other supported browsers,
// this just defines when we can count on it).
function expectSync( elem, type ) {
	return ( elem === safeActiveElement() ) === ( type === "focus" );
}

// Support: IE <=9 only
// Accessing document.activeElement can throw unexpectedly
// https://bugs.jquery.com/ticket/13393
function safeActiveElement() {
	try {
		return document.activeElement;
	} catch ( err ) { }
}

function on( elem, types, selector, data, fn, one ) {
	var origFn, type;

	// Types can be a map of types/handlers
	if ( typeof types === "object" ) {

		// ( types-Object, selector, data )
		if ( typeof selector !== "string" ) {

			// ( types-Object, data )
			data = data || selector;
			selector = undefined;
		}
		for ( type in types ) {
			on( elem, type, selector, data, types[ type ], one );
		}
		return elem;
	}

	if ( data == null && fn == null ) {

		// ( types, fn )
		fn = selector;
		data = selector = undefined;
	} else if ( fn == null ) {
		if ( typeof selector === "string" ) {

			// ( types, selector, fn )
			fn = data;
			data = undefined;
		} else {

			// ( types, data, fn )
			fn = data;
			data = selector;
			selector = undefined;
		}
	}
	if ( fn === false ) {
		fn = returnFalse;
	} else if ( !fn ) {
		return elem;
	}

	if ( one === 1 ) {
		origFn = fn;
		fn = function( event ) {

			// Can use an empty set, since event contains the info
			jQuery().off( event );
			return origFn.apply( this, arguments );
		};

		// Use same guid so caller can remove using origFn
		fn.guid = origFn.guid || ( origFn.guid = jQuery.guid++ );
	}
	return elem.each( function() {
		jQuery.event.add( this, types, fn, data, selector );
	} );
}

/*
 * Helper functions for managing events -- not part of the public interface.
 * Props to Dean Edwards' addEvent library for many of the ideas.
 */
jQuery.event = {

	global: {},

	add: function( elem, types, handler, data, selector ) {

		var handleObjIn, eventHandle, tmp,
			events, t, handleObj,
			special, handlers, type, namespaces, origType,
			elemData = dataPriv.get( elem );

		// Only attach events to objects that accept data
		if ( !acceptData( elem ) ) {
			return;
		}

		// Caller can pass in an object of custom data in lieu of the handler
		if ( handler.handler ) {
			handleObjIn = handler;
			handler = handleObjIn.handler;
			selector = handleObjIn.selector;
		}

		// Ensure that invalid selectors throw exceptions at attach time
		// Evaluate against documentElement in case elem is a non-element node (e.g., document)
		if ( selector ) {
			jQuery.find.matchesSelector( documentElement, selector );
		}

		// Make sure that the handler has a unique ID, used to find/remove it later
		if ( !handler.guid ) {
			handler.guid = jQuery.guid++;
		}

		// Init the element's event structure and main handler, if this is the first
		if ( !( events = elemData.events ) ) {
			events = elemData.events = Object.create( null );
		}
		if ( !( eventHandle = elemData.handle ) ) {
			eventHandle = elemData.handle = function( e ) {

				// Discard the second event of a jQuery.event.trigger() and
				// when an event is called after a page has unloaded
				return typeof jQuery !== "undefined" && jQuery.event.triggered !== e.type ?
					jQuery.event.dispatch.apply( elem, arguments ) : undefined;
			};
		}

		// Handle multiple events separated by a space
		types = ( types || "" ).match( rnothtmlwhite ) || [ "" ];
		t = types.length;
		while ( t-- ) {
			tmp = rtypenamespace.exec( types[ t ] ) || [];
			type = origType = tmp[ 1 ];
			namespaces = ( tmp[ 2 ] || "" ).split( "." ).sort();

			// There *must* be a type, no attaching namespace-only handlers
			if ( !type ) {
				continue;
			}

			// If event changes its type, use the special event handlers for the changed type
			special = jQuery.event.special[ type ] || {};

			// If selector defined, determine special event api type, otherwise given type
			type = ( selector ? special.delegateType : special.bindType ) || type;

			// Update special based on newly reset type
			special = jQuery.event.special[ type ] || {};

			// handleObj is passed to all event handlers
			handleObj = jQuery.extend( {
				type: type,
				origType: origType,
				data: data,
				handler: handler,
				guid: handler.guid,
				selector: selector,
				needsContext: selector && jQuery.expr.match.needsContext.test( selector ),
				namespace: namespaces.join( "." )
			}, handleObjIn );

			// Init the event handler queue if we're the first
			if ( !( handlers = events[ type ] ) ) {
				handlers = events[ type ] = [];
				handlers.delegateCount = 0;

				// Only use addEventListener if the special events handler returns false
				if ( !special.setup ||
					special.setup.call( elem, data, namespaces, eventHandle ) === false ) {

					if ( elem.addEventListener ) {
						elem.addEventListener( type, eventHandle );
					}
				}
			}

			if ( special.add ) {
				special.add.call( elem, handleObj );

				if ( !handleObj.handler.guid ) {
					handleObj.handler.guid = handler.guid;
				}
			}

			// Add to the element's handler list, delegates in front
			if ( selector ) {
				handlers.splice( handlers.delegateCount++, 0, handleObj );
			} else {
				handlers.push( handleObj );
			}

			// Keep track of which events have ever been used, for event optimization
			jQuery.event.global[ type ] = true;
		}

	},

	// Detach an event or set of events from an element
	remove: function( elem, types, handler, selector, mappedTypes ) {

		var j, origCount, tmp,
			events, t, handleObj,
			special, handlers, type, namespaces, origType,
			elemData = dataPriv.hasData( elem ) && dataPriv.get( elem );

		if ( !elemData || !( events = elemData.events ) ) {
			return;
		}

		// Once for each type.namespace in types; type may be omitted
		types = ( types || "" ).match( rnothtmlwhite ) || [ "" ];
		t = types.length;
		while ( t-- ) {
			tmp = rtypenamespace.exec( types[ t ] ) || [];
			type = origType = tmp[ 1 ];
			namespaces = ( tmp[ 2 ] || "" ).split( "." ).sort();

			// Unbind all events (on this namespace, if provided) for the element
			if ( !type ) {
				for ( type in events ) {
					jQuery.event.remove( elem, type + types[ t ], handler, selector, true );
				}
				continue;
			}

			special = jQuery.event.special[ type ] || {};
			type = ( selector ? special.delegateType : special.bindType ) || type;
			handlers = events[ type ] || [];
			tmp = tmp[ 2 ] &&
				new RegExp( "(^|\\.)" + namespaces.join( "\\.(?:.*\\.|)" ) + "(\\.|$)" );

			// Remove matching events
			origCount = j = handlers.length;
			while ( j-- ) {
				handleObj = handlers[ j ];

				if ( ( mappedTypes || origType === handleObj.origType ) &&
					( !handler || handler.guid === handleObj.guid ) &&
					( !tmp || tmp.test( handleObj.namespace ) ) &&
					( !selector || selector === handleObj.selector ||
						selector === "**" && handleObj.selector ) ) {
					handlers.splice( j, 1 );

					if ( handleObj.selector ) {
						handlers.delegateCount--;
					}
					if ( special.remove ) {
						special.remove.call( elem, handleObj );
					}
				}
			}

			// Remove generic event handler if we removed something and no more handlers exist
			// (avoids potential for endless recursion during removal of special event handlers)
			if ( origCount && !handlers.length ) {
				if ( !special.teardown ||
					special.teardown.call( elem, namespaces, elemData.handle ) === false ) {

					jQuery.removeEvent( elem, type, elemData.handle );
				}

				delete events[ type ];
			}
		}

		// Remove data and the expando if it's no longer used
		if ( jQuery.isEmptyObject( events ) ) {
			dataPriv.remove( elem, "handle events" );
		}
	},

	dispatch: function( nativeEvent ) {

		var i, j, ret, matched, handleObj, handlerQueue,
			args = new Array( arguments.length ),

			// Make a writable jQuery.Event from the native event object
			event = jQuery.event.fix( nativeEvent ),

			handlers = (
					dataPriv.get( this, "events" ) || Object.create( null )
				)[ event.type ] || [],
			special = jQuery.event.special[ event.type ] || {};

		// Use the fix-ed jQuery.Event rather than the (read-only) native event
		args[ 0 ] = event;

		for ( i = 1; i < arguments.length; i++ ) {
			args[ i ] = arguments[ i ];
		}

		event.delegateTarget = this;

		// Call the preDispatch hook for the mapped type, and let it bail if desired
		if ( special.preDispatch && special.preDispatch.call( this, event ) === false ) {
			return;
		}

		// Determine handlers
		handlerQueue = jQuery.event.handlers.call( this, event, handlers );

		// Run delegates first; they may want to stop propagation beneath us
		i = 0;
		while ( ( matched = handlerQueue[ i++ ] ) && !event.isPropagationStopped() ) {
			event.currentTarget = matched.elem;

			j = 0;
			while ( ( handleObj = matched.handlers[ j++ ] ) &&
				!event.isImmediatePropagationStopped() ) {

				// If the event is namespaced, then each handler is only invoked if it is
				// specially universal or its namespaces are a superset of the event's.
				if ( !event.rnamespace || handleObj.namespace === false ||
					event.rnamespace.test( handleObj.namespace ) ) {

					event.handleObj = handleObj;
					event.data = handleObj.data;

					ret = ( ( jQuery.event.special[ handleObj.origType ] || {} ).handle ||
						handleObj.handler ).apply( matched.elem, args );

					if ( ret !== undefined ) {
						if ( ( event.result = ret ) === false ) {
							event.preventDefault();
							event.stopPropagation();
						}
					}
				}
			}
		}

		// Call the postDispatch hook for the mapped type
		if ( special.postDispatch ) {
			special.postDispatch.call( this, event );
		}

		return event.result;
	},

	handlers: function( event, handlers ) {
		var i, handleObj, sel, matchedHandlers, matchedSelectors,
			handlerQueue = [],
			delegateCount = handlers.delegateCount,
			cur = event.target;

		// Find delegate handlers
		if ( delegateCount &&

			// Support: IE <=9
			// Black-hole SVG <use> instance trees (trac-13180)
			cur.nodeType &&

			// Support: Firefox <=42
			// Suppress spec-violating clicks indicating a non-primary pointer button (trac-3861)
			// https://www.w3.org/TR/DOM-Level-3-Events/#event-type-click
			// Support: IE 11 only
			// ...but not arrow key "clicks" of radio inputs, which can have `button` -1 (gh-2343)
			!( event.type === "click" && event.button >= 1 ) ) {

			for ( ; cur !== this; cur = cur.parentNode || this ) {

				// Don't check non-elements (#13208)
				// Don't process clicks on disabled elements (#6911, #8165, #11382, #11764)
				if ( cur.nodeType === 1 && !( event.type === "click" && cur.disabled === true ) ) {
					matchedHandlers = [];
					matchedSelectors = {};
					for ( i = 0; i < delegateCount; i++ ) {
						handleObj = handlers[ i ];

						// Don't conflict with Object.prototype properties (#13203)
						sel = handleObj.selector + " ";

						if ( matchedSelectors[ sel ] === undefined ) {
							matchedSelectors[ sel ] = handleObj.needsContext ?
								jQuery( sel, this ).index( cur ) > -1 :
								jQuery.find( sel, this, null, [ cur ] ).length;
						}
						if ( matchedSelectors[ sel ] ) {
							matchedHandlers.push( handleObj );
						}
					}
					if ( matchedHandlers.length ) {
						handlerQueue.push( { elem: cur, handlers: matchedHandlers } );
					}
				}
			}
		}

		// Add the remaining (directly-bound) handlers
		cur = this;
		if ( delegateCount < handlers.length ) {
			handlerQueue.push( { elem: cur, handlers: handlers.slice( delegateCount ) } );
		}

		return handlerQueue;
	},

	addProp: function( name, hook ) {
		Object.defineProperty( jQuery.Event.prototype, name, {
			enumerable: true,
			configurable: true,

			get: isFunction( hook ) ?
				function() {
					if ( this.originalEvent ) {
							return hook( this.originalEvent );
					}
				} :
				function() {
					if ( this.originalEvent ) {
							return this.originalEvent[ name ];
					}
				},

			set: function( value ) {
				Object.defineProperty( this, name, {
					enumerable: true,
					configurable: true,
					writable: true,
					value: value
				} );
			}
		} );
	},

	fix: function( originalEvent ) {
		return originalEvent[ jQuery.expando ] ?
			originalEvent :
			new jQuery.Event( originalEvent );
	},

	special: {
		load: {

			// Prevent triggered image.load events from bubbling to window.load
			noBubble: true
		},
		click: {

			// Utilize native event to ensure correct state for checkable inputs
			setup: function( data ) {

				// For mutual compressibility with _default, replace `this` access with a local var.
				// `|| data` is dead code meant only to preserve the variable through minification.
				var el = this || data;

				// Claim the first handler
				if ( rcheckableType.test( el.type ) &&
					el.click && nodeName( el, "input" ) ) {

					// dataPriv.set( el, "click", ... )
					leverageNative( el, "click", returnTrue );
				}

				// Return false to allow normal processing in the caller
				return false;
			},
			trigger: function( data ) {

				// For mutual compressibility with _default, replace `this` access with a local var.
				// `|| data` is dead code meant only to preserve the variable through minification.
				var el = this || data;

				// Force setup before triggering a click
				if ( rcheckableType.test( el.type ) &&
					el.click && nodeName( el, "input" ) ) {

					leverageNative( el, "click" );
				}

				// Return non-false to allow normal event-path propagation
				return true;
			},

			// For cross-browser consistency, suppress native .click() on links
			// Also prevent it if we're currently inside a leveraged native-event stack
			_default: function( event ) {
				var target = event.target;
				return rcheckableType.test( target.type ) &&
					target.click && nodeName( target, "input" ) &&
					dataPriv.get( target, "click" ) ||
					nodeName( target, "a" );
			}
		},

		beforeunload: {
			postDispatch: function( event ) {

				// Support: Firefox 20+
				// Firefox doesn't alert if the returnValue field is not set.
				if ( event.result !== undefined && event.originalEvent ) {
					event.originalEvent.returnValue = event.result;
				}
			}
		}
	}
};

// Ensure the presence of an event listener that handles manually-triggered
// synthetic events by interrupting progress until reinvoked in response to
// *native* events that it fires directly, ensuring that state changes have
// already occurred before other listeners are invoked.
function leverageNative( el, type, expectSync ) {

	// Missing expectSync indicates a trigger call, which must force setup through jQuery.event.add
	if ( !expectSync ) {
		if ( dataPriv.get( el, type ) === undefined ) {
			jQuery.event.add( el, type, returnTrue );
		}
		return;
	}

	// Register the controller as a special universal handler for all event namespaces
	dataPriv.set( el, type, false );
	jQuery.event.add( el, type, {
		namespace: false,
		handler: function( event ) {
			var notAsync, result,
				saved = dataPriv.get( this, type );

			if ( ( event.isTrigger & 1 ) && this[ type ] ) {

				// Interrupt processing of the outer synthetic .trigger()ed event
				// Saved data should be false in such cases, but might be a leftover capture object
				// from an async native handler (gh-4350)
				if ( !saved.length ) {

					// Store arguments for use when handling the inner native event
					// There will always be at least one argument (an event object), so this array
					// will not be confused with a leftover capture object.
					saved = slice.call( arguments );
					dataPriv.set( this, type, saved );

					// Trigger the native event and capture its result
					// Support: IE <=9 - 11+
					// focus() and blur() are asynchronous
					notAsync = expectSync( this, type );
					this[ type ]();
					result = dataPriv.get( this, type );
					if ( saved !== result || notAsync ) {
						dataPriv.set( this, type, false );
					} else {
						result = {};
					}
					if ( saved !== result ) {

						// Cancel the outer synthetic event
						event.stopImmediatePropagation();
						event.preventDefault();
						return result.value;
					}

				// If this is an inner synthetic event for an event with a bubbling surrogate
				// (focus or blur), assume that the surrogate already propagated from triggering the
				// native event and prevent that from happening again here.
				// This technically gets the ordering wrong w.r.t. to `.trigger()` (in which the
				// bubbling surrogate propagates *after* the non-bubbling base), but that seems
				// less bad than duplication.
				} else if ( ( jQuery.event.special[ type ] || {} ).delegateType ) {
					event.stopPropagation();
				}

			// If this is a native event triggered above, everything is now in order
			// Fire an inner synthetic event with the original arguments
			} else if ( saved.length ) {

				// ...and capture the result
				dataPriv.set( this, type, {
					value: jQuery.event.trigger(

						// Support: IE <=9 - 11+
						// Extend with the prototype to reset the above stopImmediatePropagation()
						jQuery.extend( saved[ 0 ], jQuery.Event.prototype ),
						saved.slice( 1 ),
						this
					)
				} );

				// Abort handling of the native event
				event.stopImmediatePropagation();
			}
		}
	} );
}

jQuery.removeEvent = function( elem, type, handle ) {

	// This "if" is needed for plain objects
	if ( elem.removeEventListener ) {
		elem.removeEventListener( type, handle );
	}
};

jQuery.Event = function( src, props ) {

	// Allow instantiation without the 'new' keyword
	if ( !( this instanceof jQuery.Event ) ) {
		return new jQuery.Event( src, props );
	}

	// Event object
	if ( src && src.type ) {
		this.originalEvent = src;
		this.type = src.type;

		// Events bubbling up the document may have been marked as prevented
		// by a handler lower down the tree; reflect the correct value.
		this.isDefaultPrevented = src.defaultPrevented ||
				src.defaultPrevented === undefined &&

				// Support: Android <=2.3 only
				src.returnValue === false ?
			returnTrue :
			returnFalse;

		// Create target properties
		// Support: Safari <=6 - 7 only
		// Target should not be a text node (#504, #13143)
		this.target = ( src.target && src.target.nodeType === 3 ) ?
			src.target.parentNode :
			src.target;

		this.currentTarget = src.currentTarget;
		this.relatedTarget = src.relatedTarget;

	// Event type
	} else {
		this.type = src;
	}

	// Put explicitly provided properties onto the event object
	if ( props ) {
		jQuery.extend( this, props );
	}

	// Create a timestamp if incoming event doesn't have one
	this.timeStamp = src && src.timeStamp || Date.now();

	// Mark it as fixed
	this[ jQuery.expando ] = true;
};

// jQuery.Event is based on DOM3 Events as specified by the ECMAScript Language Binding
// https://www.w3.org/TR/2003/WD-DOM-Level-3-Events-20030331/ecma-script-binding.html
jQuery.Event.prototype = {
	constructor: jQuery.Event,
	isDefaultPrevented: returnFalse,
	isPropagationStopped: returnFalse,
	isImmediatePropagationStopped: returnFalse,
	isSimulated: false,

	preventDefault: function() {
		var e = this.originalEvent;

		this.isDefaultPrevented = returnTrue;

		if ( e && !this.isSimulated ) {
			e.preventDefault();
		}
	},
	stopPropagation: function() {
		var e = this.originalEvent;

		this.isPropagationStopped = returnTrue;

		if ( e && !this.isSimulated ) {
			e.stopPropagation();
		}
	},
	stopImmediatePropagation: function() {
		var e = this.originalEvent;

		this.isImmediatePropagationStopped = returnTrue;

		if ( e && !this.isSimulated ) {
			e.stopImmediatePropagation();
		}

		this.stopPropagation();
	}
};

// Includes all common event props including KeyEvent and MouseEvent specific props
jQuery.each( {
	altKey: true,
	bubbles: true,
	cancelable: true,
	changedTouches: true,
	ctrlKey: true,
	detail: true,
	eventPhase: true,
	metaKey: true,
	pageX: true,
	pageY: true,
	shiftKey: true,
	view: true,
	"char": true,
	code: true,
	charCode: true,
	key: true,
	keyCode: true,
	button: true,
	buttons: true,
	clientX: true,
	clientY: true,
	offsetX: true,
	offsetY: true,
	pointerId: true,
	pointerType: true,
	screenX: true,
	screenY: true,
	targetTouches: true,
	toElement: true,
	touches: true,

	which: function( event ) {
		var button = event.button;

		// Add which for key events
		if ( event.which == null && rkeyEvent.test( event.type ) ) {
			return event.charCode != null ? event.charCode : event.keyCode;
		}

		// Add which for click: 1 === left; 2 === middle; 3 === right
		if ( !event.which && button !== undefined && rmouseEvent.test( event.type ) ) {
			if ( button & 1 ) {
				return 1;
			}

			if ( button & 2 ) {
				return 3;
			}

			if ( button & 4 ) {
				return 2;
			}

			return 0;
		}

		return event.which;
	}
}, jQuery.event.addProp );

jQuery.each( { focus: "focusin", blur: "focusout" }, function( type, delegateType ) {
	jQuery.event.special[ type ] = {

		// Utilize native event if possible so blur/focus sequence is correct
		setup: function() {

			// Claim the first handler
			// dataPriv.set( this, "focus", ... )
			// dataPriv.set( this, "blur", ... )
			leverageNative( this, type, expectSync );

			// Return false to allow normal processing in the caller
			return false;
		},
		trigger: function() {

			// Force setup before trigger
			leverageNative( this, type );

			// Return non-false to allow normal event-path propagation
			return true;
		},

		delegateType: delegateType
	};
} );

// Create mouseenter/leave events using mouseover/out and event-time checks
// so that event delegation works in jQuery.
// Do the same for pointerenter/pointerleave and pointerover/pointerout
//
// Support: Safari 7 only
// Safari sends mouseenter too often; see:
// https://bugs.chromium.org/p/chromium/issues/detail?id=470258
// for the description of the bug (it existed in older Chrome versions as well).
jQuery.each( {
	mouseenter: "mouseover",
	mouseleave: "mouseout",
	pointerenter: "pointerover",
	pointerleave: "pointerout"
}, function( orig, fix ) {
	jQuery.event.special[ orig ] = {
		delegateType: fix,
		bindType: fix,

		handle: function( event ) {
			var ret,
				target = this,
				related = event.relatedTarget,
				handleObj = event.handleObj;

			// For mouseenter/leave call the handler if related is outside the target.
			// NB: No relatedTarget if the mouse left/entered the browser window
			if ( !related || ( related !== target && !jQuery.contains( target, related ) ) ) {
				event.type = handleObj.origType;
				ret = handleObj.handler.apply( this, arguments );
				event.type = fix;
			}
			return ret;
		}
	};
} );

jQuery.fn.extend( {

	on: function( types, selector, data, fn ) {
		return on( this, types, selector, data, fn );
	},
	one: function( types, selector, data, fn ) {
		return on( this, types, selector, data, fn, 1 );
	},
	off: function( types, selector, fn ) {
		var handleObj, type;
		if ( types && types.preventDefault && types.handleObj ) {

			// ( event )  dispatched jQuery.Event
			handleObj = types.handleObj;
			jQuery( types.delegateTarget ).off(
				handleObj.namespace ?
					handleObj.origType + "." + handleObj.namespace :
					handleObj.origType,
				handleObj.selector,
				handleObj.handler
			);
			return this;
		}
		if ( typeof types === "object" ) {

			// ( types-object [, selector] )
			for ( type in types ) {
				this.off( type, selector, types[ type ] );
			}
			return this;
		}
		if ( selector === false || typeof selector === "function" ) {

			// ( types [, fn] )
			fn = selector;
			selector = undefined;
		}
		if ( fn === false ) {
			fn = returnFalse;
		}
		return this.each( function() {
			jQuery.event.remove( this, types, fn, selector );
		} );
	}
} );


var

	// Support: IE <=10 - 11, Edge 12 - 13 only
	// In IE/Edge using regex groups here causes severe slowdowns.
	// See https://connect.microsoft.com/IE/feedback/details/1736512/
	rnoInnerhtml = /<script|<style|<link/i,

	// checked="checked" or checked
	rchecked = /checked\s*(?:[^=]|=\s*.checked.)/i,
	rcleanScript = /^\s*<!(?:\[CDATA\[|--)|(?:\]\]|--)>\s*$/g;

// Prefer a tbody over its parent table for containing new rows
function manipulationTarget( elem, content ) {
	if ( nodeName( elem, "table" ) &&
		nodeName( content.nodeType !== 11 ? content : content.firstChild, "tr" ) ) {

		return jQuery( elem ).children( "tbody" )[ 0 ] || elem;
	}

	return elem;
}

// Replace/restore the type attribute of script elements for safe DOM manipulation
function disableScript( elem ) {
	elem.type = ( elem.getAttribute( "type" ) !== null ) + "/" + elem.type;
	return elem;
}
function restoreScript( elem ) {
	if ( ( elem.type || "" ).slice( 0, 5 ) === "true/" ) {
		elem.type = elem.type.slice( 5 );
	} else {
		elem.removeAttribute( "type" );
	}

	return elem;
}

function cloneCopyEvent( src, dest ) {
	var i, l, type, pdataOld, udataOld, udataCur, events;

	if ( dest.nodeType !== 1 ) {
		return;
	}

	// 1. Copy private data: events, handlers, etc.
	if ( dataPriv.hasData( src ) ) {
		pdataOld = dataPriv.get( src );
		events = pdataOld.events;

		if ( events ) {
			dataPriv.remove( dest, "handle events" );

			for ( type in events ) {
				for ( i = 0, l = events[ type ].length; i < l; i++ ) {
					jQuery.event.add( dest, type, events[ type ][ i ] );
				}
			}
		}
	}

	// 2. Copy user data
	if ( dataUser.hasData( src ) ) {
		udataOld = dataUser.access( src );
		udataCur = jQuery.extend( {}, udataOld );

		dataUser.set( dest, udataCur );
	}
}

// Fix IE bugs, see support tests
function fixInput( src, dest ) {
	var nodeName = dest.nodeName.toLowerCase();

	// Fails to persist the checked state of a cloned checkbox or radio button.
	if ( nodeName === "input" && rcheckableType.test( src.type ) ) {
		dest.checked = src.checked;

	// Fails to return the selected option to the default selected state when cloning options
	} else if ( nodeName === "input" || nodeName === "textarea" ) {
		dest.defaultValue = src.defaultValue;
	}
}

function domManip( collection, args, callback, ignored ) {

	// Flatten any nested arrays
	args = flat( args );

	var fragment, first, scripts, hasScripts, node, doc,
		i = 0,
		l = collection.length,
		iNoClone = l - 1,
		value = args[ 0 ],
		valueIsFunction = isFunction( value );

	// We can't cloneNode fragments that contain checked, in WebKit
	if ( valueIsFunction ||
			( l > 1 && typeof value === "string" &&
				!support.checkClone && rchecked.test( value ) ) ) {
		return collection.each( function( index ) {
			var self = collection.eq( index );
			if ( valueIsFunction ) {
				args[ 0 ] = value.call( this, index, self.html() );
			}
			domManip( self, args, callback, ignored );
		} );
	}

	if ( l ) {
		fragment = buildFragment( args, collection[ 0 ].ownerDocument, false, collection, ignored );
		first = fragment.firstChild;

		if ( fragment.childNodes.length === 1 ) {
			fragment = first;
		}

		// Require either new content or an interest in ignored elements to invoke the callback
		if ( first || ignored ) {
			scripts = jQuery.map( getAll( fragment, "script" ), disableScript );
			hasScripts = scripts.length;

			// Use the original fragment for the last item
			// instead of the first because it can end up
			// being emptied incorrectly in certain situations (#8070).
			for ( ; i < l; i++ ) {
				node = fragment;

				if ( i !== iNoClone ) {
					node = jQuery.clone( node, true, true );

					// Keep references to cloned scripts for later restoration
					if ( hasScripts ) {

						// Support: Android <=4.0 only, PhantomJS 1 only
						// push.apply(_, arraylike) throws on ancient WebKit
						jQuery.merge( scripts, getAll( node, "script" ) );
					}
				}

				callback.call( collection[ i ], node, i );
			}

			if ( hasScripts ) {
				doc = scripts[ scripts.length - 1 ].ownerDocument;

				// Reenable scripts
				jQuery.map( scripts, restoreScript );

				// Evaluate executable scripts on first document insertion
				for ( i = 0; i < hasScripts; i++ ) {
					node = scripts[ i ];
					if ( rscriptType.test( node.type || "" ) &&
						!dataPriv.access( node, "globalEval" ) &&
						jQuery.contains( doc, node ) ) {

						if ( node.src && ( node.type || "" ).toLowerCase()  !== "module" ) {

							// Optional AJAX dependency, but won't run scripts if not present
							if ( jQuery._evalUrl && !node.noModule ) {
								jQuery._evalUrl( node.src, {
									nonce: node.nonce || node.getAttribute( "nonce" )
								}, doc );
							}
						} else {
							DOMEval( node.textContent.replace( rcleanScript, "" ), node, doc );
						}
					}
				}
			}
		}
	}

	return collection;
}

function remove( elem, selector, keepData ) {
	var node,
		nodes = selector ? jQuery.filter( selector, elem ) : elem,
		i = 0;

	for ( ; ( node = nodes[ i ] ) != null; i++ ) {
		if ( !keepData && node.nodeType === 1 ) {
			jQuery.cleanData( getAll( node ) );
		}

		if ( node.parentNode ) {
			if ( keepData && isAttached( node ) ) {
				setGlobalEval( getAll( node, "script" ) );
			}
			node.parentNode.removeChild( node );
		}
	}

	return elem;
}

jQuery.extend( {
	htmlPrefilter: function( html ) {
		return html;
	},

	clone: function( elem, dataAndEvents, deepDataAndEvents ) {
		var i, l, srcElements, destElements,
			clone = elem.cloneNode( true ),
			inPage = isAttached( elem );

		// Fix IE cloning issues
		if ( !support.noCloneChecked && ( elem.nodeType === 1 || elem.nodeType === 11 ) &&
				!jQuery.isXMLDoc( elem ) ) {

			// We eschew Sizzle here for performance reasons: https://jsperf.com/getall-vs-sizzle/2
			destElements = getAll( clone );
			srcElements = getAll( elem );

			for ( i = 0, l = srcElements.length; i < l; i++ ) {
				fixInput( srcElements[ i ], destElements[ i ] );
			}
		}

		// Copy the events from the original to the clone
		if ( dataAndEvents ) {
			if ( deepDataAndEvents ) {
				srcElements = srcElements || getAll( elem );
				destElements = destElements || getAll( clone );

				for ( i = 0, l = srcElements.length; i < l; i++ ) {
					cloneCopyEvent( srcElements[ i ], destElements[ i ] );
				}
			} else {
				cloneCopyEvent( elem, clone );
			}
		}

		// Preserve script evaluation history
		destElements = getAll( clone, "script" );
		if ( destElements.length > 0 ) {
			setGlobalEval( destElements, !inPage && getAll( elem, "script" ) );
		}

		// Return the cloned set
		return clone;
	},

	cleanData: function( elems ) {
		var data, elem, type,
			special = jQuery.event.special,
			i = 0;

		for ( ; ( elem = elems[ i ] ) !== undefined; i++ ) {
			if ( acceptData( elem ) ) {
				if ( ( data = elem[ dataPriv.expando ] ) ) {
					if ( data.events ) {
						for ( type in data.events ) {
							if ( special[ type ] ) {
								jQuery.event.remove( elem, type );

							// This is a shortcut to avoid jQuery.event.remove's overhead
							} else {
								jQuery.removeEvent( elem, type, data.handle );
							}
						}
					}

					// Support: Chrome <=35 - 45+
					// Assign undefined instead of using delete, see Data#remove
					elem[ dataPriv.expando ] = undefined;
				}
				if ( elem[ dataUser.expando ] ) {

					// Support: Chrome <=35 - 45+
					// Assign undefined instead of using delete, see Data#remove
					elem[ dataUser.expando ] = undefined;
				}
			}
		}
	}
} );

jQuery.fn.extend( {
	detach: function( selector ) {
		return remove( this, selector, true );
	},

	remove: function( selector ) {
		return remove( this, selector );
	},

	text: function( value ) {
		return access( this, function( value ) {
			return value === undefined ?
				jQuery.text( this ) :
				this.empty().each( function() {
					if ( this.nodeType === 1 || this.nodeType === 11 || this.nodeType === 9 ) {
						this.textContent = value;
					}
				} );
		}, null, value, arguments.length );
	},

	append: function() {
		return domManip( this, arguments, function( elem ) {
			if ( this.nodeType === 1 || this.nodeType === 11 || this.nodeType === 9 ) {
				var target = manipulationTarget( this, elem );
				target.appendChild( elem );
			}
		} );
	},

	prepend: function() {
		return domManip( this, arguments, function( elem ) {
			if ( this.nodeType === 1 || this.nodeType === 11 || this.nodeType === 9 ) {
				var target = manipulationTarget( this, elem );
				target.insertBefore( elem, target.firstChild );
			}
		} );
	},

	before: function() {
		return domManip( this, arguments, function( elem ) {
			if ( this.parentNode ) {
				this.parentNode.insertBefore( elem, this );
			}
		} );
	},

	after: function() {
		return domManip( this, arguments, function( elem ) {
			if ( this.parentNode ) {
				this.parentNode.insertBefore( elem, this.nextSibling );
			}
		} );
	},

	empty: function() {
		var elem,
			i = 0;

		for ( ; ( elem = this[ i ] ) != null; i++ ) {
			if ( elem.nodeType === 1 ) {

				// Prevent memory leaks
				jQuery.cleanData( getAll( elem, false ) );

				// Remove any remaining nodes
				elem.textContent = "";
			}
		}

		return this;
	},

	clone: function( dataAndEvents, deepDataAndEvents ) {
		dataAndEvents = dataAndEvents == null ? false : dataAndEvents;
		deepDataAndEvents = deepDataAndEvents == null ? dataAndEvents : deepDataAndEvents;

		return this.map( function() {
			return jQuery.clone( this, dataAndEvents, deepDataAndEvents );
		} );
	},

	html: function( value ) {
		return access( this, function( value ) {
			var elem = this[ 0 ] || {},
				i = 0,
				l = this.length;

			if ( value === undefined && elem.nodeType === 1 ) {
				return elem.innerHTML;
			}

			// See if we can take a shortcut and just use innerHTML
			if ( typeof value === "string" && !rnoInnerhtml.test( value ) &&
				!wrapMap[ ( rtagName.exec( value ) || [ "", "" ] )[ 1 ].toLowerCase() ] ) {

				value = jQuery.htmlPrefilter( value );

				try {
					for ( ; i < l; i++ ) {
						elem = this[ i ] || {};

						// Remove element nodes and prevent memory leaks
						if ( elem.nodeType === 1 ) {
							jQuery.cleanData( getAll( elem, false ) );
							elem.innerHTML = value;
						}
					}

					elem = 0;

				// If using innerHTML throws an exception, use the fallback method
				} catch ( e ) {}
			}

			if ( elem ) {
				this.empty().append( value );
			}
		}, null, value, arguments.length );
	},

	replaceWith: function() {
		var ignored = [];

		// Make the changes, replacing each non-ignored context element with the new content
		return domManip( this, arguments, function( elem ) {
			var parent = this.parentNode;

			if ( jQuery.inArray( this, ignored ) < 0 ) {
				jQuery.cleanData( getAll( this ) );
				if ( parent ) {
					parent.replaceChild( elem, this );
				}
			}

		// Force callback invocation
		}, ignored );
	}
} );

jQuery.each( {
	appendTo: "append",
	prependTo: "prepend",
	insertBefore: "before",
	insertAfter: "after",
	replaceAll: "replaceWith"
}, function( name, original ) {
	jQuery.fn[ name ] = function( selector ) {
		var elems,
			ret = [],
			insert = jQuery( selector ),
			last = insert.length - 1,
			i = 0;

		for ( ; i <= last; i++ ) {
			elems = i === last ? this : this.clone( true );
			jQuery( insert[ i ] )[ original ]( elems );

			// Support: Android <=4.0 only, PhantomJS 1 only
			// .get() because push.apply(_, arraylike) throws on ancient WebKit
			push.apply( ret, elems.get() );
		}

		return this.pushStack( ret );
	};
} );
var rnumnonpx = new RegExp( "^(" + pnum + ")(?!px)[a-z%]+$", "i" );

var getStyles = function( elem ) {

		// Support: IE <=11 only, Firefox <=30 (#15098, #14150)
		// IE throws on elements created in popups
		// FF meanwhile throws on frame elements through "defaultView.getComputedStyle"
		var view = elem.ownerDocument.defaultView;

		if ( !view || !view.opener ) {
			view = window;
		}

		return view.getComputedStyle( elem );
	};

var swap = function( elem, options, callback ) {
	var ret, name,
		old = {};

	// Remember the old values, and insert the new ones
	for ( name in options ) {
		old[ name ] = elem.style[ name ];
		elem.style[ name ] = options[ name ];
	}

	ret = callback.call( elem );

	// Revert the old values
	for ( name in options ) {
		elem.style[ name ] = old[ name ];
	}

	return ret;
};


var rboxStyle = new RegExp( cssExpand.join( "|" ), "i" );



( function() {

	// Executing both pixelPosition & boxSizingReliable tests require only one layout
	// so they're executed at the same time to save the second computation.
	function computeStyleTests() {

		// This is a singleton, we need to execute it only once
		if ( !div ) {
			return;
		}

		container.style.cssText = "position:absolute;left:-11111px;width:60px;" +
			"margin-top:1px;padding:0;border:0";
		div.style.cssText =
			"position:relative;display:block;box-sizing:border-box;overflow:scroll;" +
			"margin:auto;border:1px;padding:1px;" +
			"width:60%;top:1%";
		documentElement.appendChild( container ).appendChild( div );

		var divStyle = window.getComputedStyle( div );
		pixelPositionVal = divStyle.top !== "1%";

		// Support: Android 4.0 - 4.3 only, Firefox <=3 - 44
		reliableMarginLeftVal = roundPixelMeasures( divStyle.marginLeft ) === 12;

		// Support: Android 4.0 - 4.3 only, Safari <=9.1 - 10.1, iOS <=7.0 - 9.3
		// Some styles come back with percentage values, even though they shouldn't
		div.style.right = "60%";
		pixelBoxStylesVal = roundPixelMeasures( divStyle.right ) === 36;

		// Support: IE 9 - 11 only
		// Detect misreporting of content dimensions for box-sizing:border-box elements
		boxSizingReliableVal = roundPixelMeasures( divStyle.width ) === 36;

		// Support: IE 9 only
		// Detect overflow:scroll screwiness (gh-3699)
		// Support: Chrome <=64
		// Don't get tricked when zoom affects offsetWidth (gh-4029)
		div.style.position = "absolute";
		scrollboxSizeVal = roundPixelMeasures( div.offsetWidth / 3 ) === 12;

		documentElement.removeChild( container );

		// Nullify the div so it wouldn't be stored in the memory and
		// it will also be a sign that checks already performed
		div = null;
	}

	function roundPixelMeasures( measure ) {
		return Math.round( parseFloat( measure ) );
	}

	var pixelPositionVal, boxSizingReliableVal, scrollboxSizeVal, pixelBoxStylesVal,
		reliableTrDimensionsVal, reliableMarginLeftVal,
		container = document.createElement( "div" ),
		div = document.createElement( "div" );

	// Finish early in limited (non-browser) environments
	if ( !div.style ) {
		return;
	}

	// Support: IE <=9 - 11 only
	// Style of cloned element affects source element cloned (#8908)
	div.style.backgroundClip = "content-box";
	div.cloneNode( true ).style.backgroundClip = "";
	support.clearCloneStyle = div.style.backgroundClip === "content-box";

	jQuery.extend( support, {
		boxSizingReliable: function() {
			computeStyleTests();
			return boxSizingReliableVal;
		},
		pixelBoxStyles: function() {
			computeStyleTests();
			return pixelBoxStylesVal;
		},
		pixelPosition: function() {
			computeStyleTests();
			return pixelPositionVal;
		},
		reliableMarginLeft: function() {
			computeStyleTests();
			return reliableMarginLeftVal;
		},
		scrollboxSize: function() {
			computeStyleTests();
			return scrollboxSizeVal;
		},

		// Support: IE 9 - 11+, Edge 15 - 18+
		// IE/Edge misreport `getComputedStyle` of table rows with width/height
		// set in CSS while `offset*` properties report correct values.
		// Behavior in IE 9 is more subtle than in newer versions & it passes
		// some versions of this test; make sure not to make it pass there!
		reliableTrDimensions: function() {
			var table, tr, trChild, trStyle;
			if ( reliableTrDimensionsVal == null ) {
				table = document.createElement( "table" );
				tr = document.createElement( "tr" );
				trChild = document.createElement( "div" );

				table.style.cssText = "position:absolute;left:-11111px";
				tr.style.height = "1px";
				trChild.style.height = "9px";

				documentElement
					.appendChild( table )
					.appendChild( tr )
					.appendChild( trChild );

				trStyle = window.getComputedStyle( tr );
				reliableTrDimensionsVal = parseInt( trStyle.height ) > 3;

				documentElement.removeChild( table );
			}
			return reliableTrDimensionsVal;
		}
	} );
} )();


function curCSS( elem, name, computed ) {
	var width, minWidth, maxWidth, ret,

		// Support: Firefox 51+
		// Retrieving style before computed somehow
		// fixes an issue with getting wrong values
		// on detached elements
		style = elem.style;

	computed = computed || getStyles( elem );

	// getPropertyValue is needed for:
	//   .css('filter') (IE 9 only, #12537)
	//   .css('--customProperty) (#3144)
	if ( computed ) {
		ret = computed.getPropertyValue( name ) || computed[ name ];

		if ( ret === "" && !isAttached( elem ) ) {
			ret = jQuery.style( elem, name );
		}

		// A tribute to the "awesome hack by Dean Edwards"
		// Android Browser returns percentage for some values,
		// but width seems to be reliably pixels.
		// This is against the CSSOM draft spec:
		// https://drafts.csswg.org/cssom/#resolved-values
		if ( !support.pixelBoxStyles() && rnumnonpx.test( ret ) && rboxStyle.test( name ) ) {

			// Remember the original values
			width = style.width;
			minWidth = style.minWidth;
			maxWidth = style.maxWidth;

			// Put in the new values to get a computed value out
			style.minWidth = style.maxWidth = style.width = ret;
			ret = computed.width;

			// Revert the changed values
			style.width = width;
			style.minWidth = minWidth;
			style.maxWidth = maxWidth;
		}
	}

	return ret !== undefined ?

		// Support: IE <=9 - 11 only
		// IE returns zIndex value as an integer.
		ret + "" :
		ret;
}


function addGetHookIf( conditionFn, hookFn ) {

	// Define the hook, we'll check on the first run if it's really needed.
	return {
		get: function() {
			if ( conditionFn() ) {

				// Hook not needed (or it's not possible to use it due
				// to missing dependency), remove it.
				delete this.get;
				return;
			}

			// Hook needed; redefine it so that the support test is not executed again.
			return ( this.get = hookFn ).apply( this, arguments );
		}
	};
}


var cssPrefixes = [ "Webkit", "Moz", "ms" ],
	emptyStyle = document.createElement( "div" ).style,
	vendorProps = {};

// Return a vendor-prefixed property or undefined
function vendorPropName( name ) {

	// Check for vendor prefixed names
	var capName = name[ 0 ].toUpperCase() + name.slice( 1 ),
		i = cssPrefixes.length;

	while ( i-- ) {
		name = cssPrefixes[ i ] + capName;
		if ( name in emptyStyle ) {
			return name;
		}
	}
}

// Return a potentially-mapped jQuery.cssProps or vendor prefixed property
function finalPropName( name ) {
	var final = jQuery.cssProps[ name ] || vendorProps[ name ];

	if ( final ) {
		return final;
	}
	if ( name in emptyStyle ) {
		return name;
	}
	return vendorProps[ name ] = vendorPropName( name ) || name;
}


var

	// Swappable if display is none or starts with table
	// except "table", "table-cell", or "table-caption"
	// See here for display values: https://developer.mozilla.org/en-US/docs/CSS/display
	rdisplayswap = /^(none|table(?!-c[ea]).+)/,
	rcustomProp = /^--/,
	cssShow = { position: "absolute", visibility: "hidden", display: "block" },
	cssNormalTransform = {
		letterSpacing: "0",
		fontWeight: "400"
	};

function setPositiveNumber( _elem, value, subtract ) {

	// Any relative (+/-) values have already been
	// normalized at this point
	var matches = rcssNum.exec( value );
	return matches ?

		// Guard against undefined "subtract", e.g., when used as in cssHooks
		Math.max( 0, matches[ 2 ] - ( subtract || 0 ) ) + ( matches[ 3 ] || "px" ) :
		value;
}

function boxModelAdjustment( elem, dimension, box, isBorderBox, styles, computedVal ) {
	var i = dimension === "width" ? 1 : 0,
		extra = 0,
		delta = 0;

	// Adjustment may not be necessary
	if ( box === ( isBorderBox ? "border" : "content" ) ) {
		return 0;
	}

	for ( ; i < 4; i += 2 ) {

		// Both box models exclude margin
		if ( box === "margin" ) {
			delta += jQuery.css( elem, box + cssExpand[ i ], true, styles );
		}

		// If we get here with a content-box, we're seeking "padding" or "border" or "margin"
		if ( !isBorderBox ) {

			// Add padding
			delta += jQuery.css( elem, "padding" + cssExpand[ i ], true, styles );

			// For "border" or "margin", add border
			if ( box !== "padding" ) {
				delta += jQuery.css( elem, "border" + cssExpand[ i ] + "Width", true, styles );

			// But still keep track of it otherwise
			} else {
				extra += jQuery.css( elem, "border" + cssExpand[ i ] + "Width", true, styles );
			}

		// If we get here with a border-box (content + padding + border), we're seeking "content" or
		// "padding" or "margin"
		} else {

			// For "content", subtract padding
			if ( box === "content" ) {
				delta -= jQuery.css( elem, "padding" + cssExpand[ i ], true, styles );
			}

			// For "content" or "padding", subtract border
			if ( box !== "margin" ) {
				delta -= jQuery.css( elem, "border" + cssExpand[ i ] + "Width", true, styles );
			}
		}
	}

	// Account for positive content-box scroll gutter when requested by providing computedVal
	if ( !isBorderBox && computedVal >= 0 ) {

		// offsetWidth/offsetHeight is a rounded sum of content, padding, scroll gutter, and border
		// Assuming integer scroll gutter, subtract the rest and round down
		delta += Math.max( 0, Math.ceil(
			elem[ "offset" + dimension[ 0 ].toUpperCase() + dimension.slice( 1 ) ] -
			computedVal -
			delta -
			extra -
			0.5

		// If offsetWidth/offsetHeight is unknown, then we can't determine content-box scroll gutter
		// Use an explicit zero to avoid NaN (gh-3964)
		) ) || 0;
	}

	return delta;
}

function getWidthOrHeight( elem, dimension, extra ) {

	// Start with computed style
	var styles = getStyles( elem ),

		// To avoid forcing a reflow, only fetch boxSizing if we need it (gh-4322).
		// Fake content-box until we know it's needed to know the true value.
		boxSizingNeeded = !support.boxSizingReliable() || extra,
		isBorderBox = boxSizingNeeded &&
			jQuery.css( elem, "boxSizing", false, styles ) === "border-box",
		valueIsBorderBox = isBorderBox,

		val = curCSS( elem, dimension, styles ),
		offsetProp = "offset" + dimension[ 0 ].toUpperCase() + dimension.slice( 1 );

	// Support: Firefox <=54
	// Return a confounding non-pixel value or feign ignorance, as appropriate.
	if ( rnumnonpx.test( val ) ) {
		if ( !extra ) {
			return val;
		}
		val = "auto";
	}


	// Support: IE 9 - 11 only
	// Use offsetWidth/offsetHeight for when box sizing is unreliable.
	// In those cases, the computed value can be trusted to be border-box.
	if ( ( !support.boxSizingReliable() && isBorderBox ||

		// Support: IE 10 - 11+, Edge 15 - 18+
		// IE/Edge misreport `getComputedStyle` of table rows with width/height
		// set in CSS while `offset*` properties report correct values.
		// Interestingly, in some cases IE 9 doesn't suffer from this issue.
		!support.reliableTrDimensions() && nodeName( elem, "tr" ) ||

		// Fall back to offsetWidth/offsetHeight when value is "auto"
		// This happens for inline elements with no explicit setting (gh-3571)
		val === "auto" ||

		// Support: Android <=4.1 - 4.3 only
		// Also use offsetWidth/offsetHeight for misreported inline dimensions (gh-3602)
		!parseFloat( val ) && jQuery.css( elem, "display", false, styles ) === "inline" ) &&

		// Make sure the element is visible & connected
		elem.getClientRects().length ) {

		isBorderBox = jQuery.css( elem, "boxSizing", false, styles ) === "border-box";

		// Where available, offsetWidth/offsetHeight approximate border box dimensions.
		// Where not available (e.g., SVG), assume unreliable box-sizing and interpret the
		// retrieved value as a content box dimension.
		valueIsBorderBox = offsetProp in elem;
		if ( valueIsBorderBox ) {
			val = elem[ offsetProp ];
		}
	}

	// Normalize "" and auto
	val = parseFloat( val ) || 0;

	// Adjust for the element's box model
	return ( val +
		boxModelAdjustment(
			elem,
			dimension,
			extra || ( isBorderBox ? "border" : "content" ),
			valueIsBorderBox,
			styles,

			// Provide the current computed size to request scroll gutter calculation (gh-3589)
			val
		)
	) + "px";
}

jQuery.extend( {

	// Add in style property hooks for overriding the default
	// behavior of getting and setting a style property
	cssHooks: {
		opacity: {
			get: function( elem, computed ) {
				if ( computed ) {

					// We should always get a number back from opacity
					var ret = curCSS( elem, "opacity" );
					return ret === "" ? "1" : ret;
				}
			}
		}
	},

	// Don't automatically add "px" to these possibly-unitless properties
	cssNumber: {
		"animationIterationCount": true,
		"columnCount": true,
		"fillOpacity": true,
		"flexGrow": true,
		"flexShrink": true,
		"fontWeight": true,
		"gridArea": true,
		"gridColumn": true,
		"gridColumnEnd": true,
		"gridColumnStart": true,
		"gridRow": true,
		"gridRowEnd": true,
		"gridRowStart": true,
		"lineHeight": true,
		"opacity": true,
		"order": true,
		"orphans": true,
		"widows": true,
		"zIndex": true,
		"zoom": true
	},

	// Add in properties whose names you wish to fix before
	// setting or getting the value
	cssProps: {},

	// Get and set the style property on a DOM Node
	style: function( elem, name, value, extra ) {

		// Don't set styles on text and comment nodes
		if ( !elem || elem.nodeType === 3 || elem.nodeType === 8 || !elem.style ) {
			return;
		}

		// Make sure that we're working with the right name
		var ret, type, hooks,
			origName = camelCase( name ),
			isCustomProp = rcustomProp.test( name ),
			style = elem.style;

		// Make sure that we're working with the right name. We don't
		// want to query the value if it is a CSS custom property
		// since they are user-defined.
		if ( !isCustomProp ) {
			name = finalPropName( origName );
		}

		// Gets hook for the prefixed version, then unprefixed version
		hooks = jQuery.cssHooks[ name ] || jQuery.cssHooks[ origName ];

		// Check if we're setting a value
		if ( value !== undefined ) {
			type = typeof value;

			// Convert "+=" or "-=" to relative numbers (#7345)
			if ( type === "string" && ( ret = rcssNum.exec( value ) ) && ret[ 1 ] ) {
				value = adjustCSS( elem, name, ret );

				// Fixes bug #9237
				type = "number";
			}

			// Make sure that null and NaN values aren't set (#7116)
			if ( value == null || value !== value ) {
				return;
			}

			// If a number was passed in, add the unit (except for certain CSS properties)
			// The isCustomProp check can be removed in jQuery 4.0 when we only auto-append
			// "px" to a few hardcoded values.
			if ( type === "number" && !isCustomProp ) {
				value += ret && ret[ 3 ] || ( jQuery.cssNumber[ origName ] ? "" : "px" );
			}

			// background-* props affect original clone's values
			if ( !support.clearCloneStyle && value === "" && name.indexOf( "background" ) === 0 ) {
				style[ name ] = "inherit";
			}

			// If a hook was provided, use that value, otherwise just set the specified value
			if ( !hooks || !( "set" in hooks ) ||
				( value = hooks.set( elem, value, extra ) ) !== undefined ) {

				if ( isCustomProp ) {
					style.setProperty( name, value );
				} else {
					style[ name ] = value;
				}
			}

		} else {

			// If a hook was provided get the non-computed value from there
			if ( hooks && "get" in hooks &&
				( ret = hooks.get( elem, false, extra ) ) !== undefined ) {

				return ret;
			}

			// Otherwise just get the value from the style object
			return style[ name ];
		}
	},

	css: function( elem, name, extra, styles ) {
		var val, num, hooks,
			origName = camelCase( name ),
			isCustomProp = rcustomProp.test( name );

		// Make sure that we're working with the right name. We don't
		// want to modify the value if it is a CSS custom property
		// since they are user-defined.
		if ( !isCustomProp ) {
			name = finalPropName( origName );
		}

		// Try prefixed name followed by the unprefixed name
		hooks = jQuery.cssHooks[ name ] || jQuery.cssHooks[ origName ];

		// If a hook was provided get the computed value from there
		if ( hooks && "get" in hooks ) {
			val = hooks.get( elem, true, extra );
		}

		// Otherwise, if a way to get the computed value exists, use that
		if ( val === undefined ) {
			val = curCSS( elem, name, styles );
		}

		// Convert "normal" to computed value
		if ( val === "normal" && name in cssNormalTransform ) {
			val = cssNormalTransform[ name ];
		}

		// Make numeric if forced or a qualifier was provided and val looks numeric
		if ( extra === "" || extra ) {
			num = parseFloat( val );
			return extra === true || isFinite( num ) ? num || 0 : val;
		}

		return val;
	}
} );

jQuery.each( [ "height", "width" ], function( _i, dimension ) {
	jQuery.cssHooks[ dimension ] = {
		get: function( elem, computed, extra ) {
			if ( computed ) {

				// Certain elements can have dimension info if we invisibly show them
				// but it must have a current display style that would benefit
				return rdisplayswap.test( jQuery.css( elem, "display" ) ) &&

					// Support: Safari 8+
					// Table columns in Safari have non-zero offsetWidth & zero
					// getBoundingClientRect().width unless display is changed.
					// Support: IE <=11 only
					// Running getBoundingClientRect on a disconnected node
					// in IE throws an error.
					( !elem.getClientRects().length || !elem.getBoundingClientRect().width ) ?
						swap( elem, cssShow, function() {
							return getWidthOrHeight( elem, dimension, extra );
						} ) :
						getWidthOrHeight( elem, dimension, extra );
			}
		},

		set: function( elem, value, extra ) {
			var matches,
				styles = getStyles( elem ),

				// Only read styles.position if the test has a chance to fail
				// to avoid forcing a reflow.
				scrollboxSizeBuggy = !support.scrollboxSize() &&
					styles.position === "absolute",

				// To avoid forcing a reflow, only fetch boxSizing if we need it (gh-3991)
				boxSizingNeeded = scrollboxSizeBuggy || extra,
				isBorderBox = boxSizingNeeded &&
					jQuery.css( elem, "boxSizing", false, styles ) === "border-box",
				subtract = extra ?
					boxModelAdjustment(
						elem,
						dimension,
						extra,
						isBorderBox,
						styles
					) :
					0;

			// Account for unreliable border-box dimensions by comparing offset* to computed and
			// faking a content-box to get border and padding (gh-3699)
			if ( isBorderBox && scrollboxSizeBuggy ) {
				subtract -= Math.ceil(
					elem[ "offset" + dimension[ 0 ].toUpperCase() + dimension.slice( 1 ) ] -
					parseFloat( styles[ dimension ] ) -
					boxModelAdjustment( elem, dimension, "border", false, styles ) -
					0.5
				);
			}

			// Convert to pixels if value adjustment is needed
			if ( subtract && ( matches = rcssNum.exec( value ) ) &&
				( matches[ 3 ] || "px" ) !== "px" ) {

				elem.style[ dimension ] = value;
				value = jQuery.css( elem, dimension );
			}

			return setPositiveNumber( elem, value, subtract );
		}
	};
} );

jQuery.cssHooks.marginLeft = addGetHookIf( support.reliableMarginLeft,
	function( elem, computed ) {
		if ( computed ) {
			return ( parseFloat( curCSS( elem, "marginLeft" ) ) ||
				elem.getBoundingClientRect().left -
					swap( elem, { marginLeft: 0 }, function() {
						return elem.getBoundingClientRect().left;
					} )
				) + "px";
		}
	}
);

// These hooks are used by animate to expand properties
jQuery.each( {
	margin: "",
	padding: "",
	border: "Width"
}, function( prefix, suffix ) {
	jQuery.cssHooks[ prefix + suffix ] = {
		expand: function( value ) {
			var i = 0,
				expanded = {},

				// Assumes a single number if not a string
				parts = typeof value === "string" ? value.split( " " ) : [ value ];

			for ( ; i < 4; i++ ) {
				expanded[ prefix + cssExpand[ i ] + suffix ] =
					parts[ i ] || parts[ i - 2 ] || parts[ 0 ];
			}

			return expanded;
		}
	};

	if ( prefix !== "margin" ) {
		jQuery.cssHooks[ prefix + suffix ].set = setPositiveNumber;
	}
} );

jQuery.fn.extend( {
	css: function( name, value ) {
		return access( this, function( elem, name, value ) {
			var styles, len,
				map = {},
				i = 0;

			if ( Array.isArray( name ) ) {
				styles = getStyles( elem );
				len = name.length;

				for ( ; i < len; i++ ) {
					map[ name[ i ] ] = jQuery.css( elem, name[ i ], false, styles );
				}

				return map;
			}

			return value !== undefined ?
				jQuery.style( elem, name, value ) :
				jQuery.css( elem, name );
		}, name, value, arguments.length > 1 );
	}
} );


function Tween( elem, options, prop, end, easing ) {
	return new Tween.prototype.init( elem, options, prop, end, easing );
}
jQuery.Tween = Tween;

Tween.prototype = {
	constructor: Tween,
	init: function( elem, options, prop, end, easing, unit ) {
		this.elem = elem;
		this.prop = prop;
		this.easing = easing || jQuery.easing._default;
		this.options = options;
		this.start = this.now = this.cur();
		this.end = end;
		this.unit = unit || ( jQuery.cssNumber[ prop ] ? "" : "px" );
	},
	cur: function() {
		var hooks = Tween.propHooks[ this.prop ];

		return hooks && hooks.get ?
			hooks.get( this ) :
			Tween.propHooks._default.get( this );
	},
	run: function( percent ) {
		var eased,
			hooks = Tween.propHooks[ this.prop ];

		if ( this.options.duration ) {
			this.pos = eased = jQuery.easing[ this.easing ](
				percent, this.options.duration * percent, 0, 1, this.options.duration
			);
		} else {
			this.pos = eased = percent;
		}
		this.now = ( this.end - this.start ) * eased + this.start;

		if ( this.options.step ) {
			this.options.step.call( this.elem, this.now, this );
		}

		if ( hooks && hooks.set ) {
			hooks.set( this );
		} else {
			Tween.propHooks._default.set( this );
		}
		return this;
	}
};

Tween.prototype.init.prototype = Tween.prototype;

Tween.propHooks = {
	_default: {
		get: function( tween ) {
			var result;

			// Use a property on the element directly when it is not a DOM element,
			// or when there is no matching style property that exists.
			if ( tween.elem.nodeType !== 1 ||
				tween.elem[ tween.prop ] != null && tween.elem.style[ tween.prop ] == null ) {
				return tween.elem[ tween.prop ];
			}

			// Passing an empty string as a 3rd parameter to .css will automatically
			// attempt a parseFloat and fallback to a string if the parse fails.
			// Simple values such as "10px" are parsed to Float;
			// complex values such as "rotate(1rad)" are returned as-is.
			result = jQuery.css( tween.elem, tween.prop, "" );

			// Empty strings, null, undefined and "auto" are converted to 0.
			return !result || result === "auto" ? 0 : result;
		},
		set: function( tween ) {

			// Use step hook for back compat.
			// Use cssHook if its there.
			// Use .style if available and use plain properties where available.
			if ( jQuery.fx.step[ tween.prop ] ) {
				jQuery.fx.step[ tween.prop ]( tween );
			} else if ( tween.elem.nodeType === 1 && (
					jQuery.cssHooks[ tween.prop ] ||
					tween.elem.style[ finalPropName( tween.prop ) ] != null ) ) {
				jQuery.style( tween.elem, tween.prop, tween.now + tween.unit );
			} else {
				tween.elem[ tween.prop ] = tween.now;
			}
		}
	}
};

// Support: IE <=9 only
// Panic based approach to setting things on disconnected nodes
Tween.propHooks.scrollTop = Tween.propHooks.scrollLeft = {
	set: function( tween ) {
		if ( tween.elem.nodeType && tween.elem.parentNode ) {
			tween.elem[ tween.prop ] = tween.now;
		}
	}
};

jQuery.easing = {
	linear: function( p ) {
		return p;
	},
	swing: function( p ) {
		return 0.5 - Math.cos( p * Math.PI ) / 2;
	},
	_default: "swing"
};

jQuery.fx = Tween.prototype.init;

// Back compat <1.8 extension point
jQuery.fx.step = {};




var
	fxNow, inProgress,
	rfxtypes = /^(?:toggle|show|hide)$/,
	rrun = /queueHooks$/;

function schedule() {
	if ( inProgress ) {
		if ( document.hidden === false && window.requestAnimationFrame ) {
			window.requestAnimationFrame( schedule );
		} else {
			window.setTimeout( schedule, jQuery.fx.interval );
		}

		jQuery.fx.tick();
	}
}

// Animations created synchronously will run synchronously
function createFxNow() {
	window.setTimeout( function() {
		fxNow = undefined;
	} );
	return ( fxNow = Date.now() );
}

// Generate parameters to create a standard animation
function genFx( type, includeWidth ) {
	var which,
		i = 0,
		attrs = { height: type };

	// If we include width, step value is 1 to do all cssExpand values,
	// otherwise step value is 2 to skip over Left and Right
	includeWidth = includeWidth ? 1 : 0;
	for ( ; i < 4; i += 2 - includeWidth ) {
		which = cssExpand[ i ];
		attrs[ "margin" + which ] = attrs[ "padding" + which ] = type;
	}

	if ( includeWidth ) {
		attrs.opacity = attrs.width = type;
	}

	return attrs;
}

function createTween( value, prop, animation ) {
	var tween,
		collection = ( Animation.tweeners[ prop ] || [] ).concat( Animation.tweeners[ "*" ] ),
		index = 0,
		length = collection.length;
	for ( ; index < length; index++ ) {
		if ( ( tween = collection[ index ].call( animation, prop, value ) ) ) {

			// We're done with this property
			return tween;
		}
	}
}

function defaultPrefilter( elem, props, opts ) {
	var prop, value, toggle, hooks, oldfire, propTween, restoreDisplay, display,
		isBox = "width" in props || "height" in props,
		anim = this,
		orig = {},
		style = elem.style,
		hidden = elem.nodeType && isHiddenWithinTree( elem ),
		dataShow = dataPriv.get( elem, "fxshow" );

	// Queue-skipping animations hijack the fx hooks
	if ( !opts.queue ) {
		hooks = jQuery._queueHooks( elem, "fx" );
		if ( hooks.unqueued == null ) {
			hooks.unqueued = 0;
			oldfire = hooks.empty.fire;
			hooks.empty.fire = function() {
				if ( !hooks.unqueued ) {
					oldfire();
				}
			};
		}
		hooks.unqueued++;

		anim.always( function() {

			// Ensure the complete handler is called before this completes
			anim.always( function() {
				hooks.unqueued--;
				if ( !jQuery.queue( elem, "fx" ).length ) {
					hooks.empty.fire();
				}
			} );
		} );
	}

	// Detect show/hide animations
	for ( prop in props ) {
		value = props[ prop ];
		if ( rfxtypes.test( value ) ) {
			delete props[ prop ];
			toggle = toggle || value === "toggle";
			if ( value === ( hidden ? "hide" : "show" ) ) {

				// Pretend to be hidden if this is a "show" and
				// there is still data from a stopped show/hide
				if ( value === "show" && dataShow && dataShow[ prop ] !== undefined ) {
					hidden = true;

				// Ignore all other no-op show/hide data
				} else {
					continue;
				}
			}
			orig[ prop ] = dataShow && dataShow[ prop ] || jQuery.style( elem, prop );
		}
	}

	// Bail out if this is a no-op like .hide().hide()
	propTween = !jQuery.isEmptyObject( props );
	if ( !propTween && jQuery.isEmptyObject( orig ) ) {
		return;
	}

	// Restrict "overflow" and "display" styles during box animations
	if ( isBox && elem.nodeType === 1 ) {

		// Support: IE <=9 - 11, Edge 12 - 15
		// Record all 3 overflow attributes because IE does not infer the shorthand
		// from identically-valued overflowX and overflowY and Edge just mirrors
		// the overflowX value there.
		opts.overflow = [ style.overflow, style.overflowX, style.overflowY ];

		// Identify a display type, preferring old show/hide data over the CSS cascade
		restoreDisplay = dataShow && dataShow.display;
		if ( restoreDisplay == null ) {
			restoreDisplay = dataPriv.get( elem, "display" );
		}
		display = jQuery.css( elem, "display" );
		if ( display === "none" ) {
			if ( restoreDisplay ) {
				display = restoreDisplay;
			} else {

				// Get nonempty value(s) by temporarily forcing visibility
				showHide( [ elem ], true );
				restoreDisplay = elem.style.display || restoreDisplay;
				display = jQuery.css( elem, "display" );
				showHide( [ elem ] );
			}
		}

		// Animate inline elements as inline-block
		if ( display === "inline" || display === "inline-block" && restoreDisplay != null ) {
			if ( jQuery.css( elem, "float" ) === "none" ) {

				// Restore the original display value at the end of pure show/hide animations
				if ( !propTween ) {
					anim.done( function() {
						style.display = restoreDisplay;
					} );
					if ( restoreDisplay == null ) {
						display = style.display;
						restoreDisplay = display === "none" ? "" : display;
					}
				}
				style.display = "inline-block";
			}
		}
	}

	if ( opts.overflow ) {
		style.overflow = "hidden";
		anim.always( function() {
			style.overflow = opts.overflow[ 0 ];
			style.overflowX = opts.overflow[ 1 ];
			style.overflowY = opts.overflow[ 2 ];
		} );
	}

	// Implement show/hide animations
	propTween = false;
	for ( prop in orig ) {

		// General show/hide setup for this element animation
		if ( !propTween ) {
			if ( dataShow ) {
				if ( "hidden" in dataShow ) {
					hidden = dataShow.hidden;
				}
			} else {
				dataShow = dataPriv.access( elem, "fxshow", { display: restoreDisplay } );
			}

			// Store hidden/visible for toggle so `.stop().toggle()` "reverses"
			if ( toggle ) {
				dataShow.hidden = !hidden;
			}

			// Show elements before animating them
			if ( hidden ) {
				showHide( [ elem ], true );
			}

			/* eslint-disable no-loop-func */

			anim.done( function() {

			/* eslint-enable no-loop-func */

				// The final step of a "hide" animation is actually hiding the element
				if ( !hidden ) {
					showHide( [ elem ] );
				}
				dataPriv.remove( elem, "fxshow" );
				for ( prop in orig ) {
					jQuery.style( elem, prop, orig[ prop ] );
				}
			} );
		}

		// Per-property setup
		propTween = createTween( hidden ? dataShow[ prop ] : 0, prop, anim );
		if ( !( prop in dataShow ) ) {
			dataShow[ prop ] = propTween.start;
			if ( hidden ) {
				propTween.end = propTween.start;
				propTween.start = 0;
			}
		}
	}
}

function propFilter( props, specialEasing ) {
	var index, name, easing, value, hooks;

	// camelCase, specialEasing and expand cssHook pass
	for ( index in props ) {
		name = camelCase( index );
		easing = specialEasing[ name ];
		value = props[ index ];
		if ( Array.isArray( value ) ) {
			easing = value[ 1 ];
			value = props[ index ] = value[ 0 ];
		}

		if ( index !== name ) {
			props[ name ] = value;
			delete props[ index ];
		}

		hooks = jQuery.cssHooks[ name ];
		if ( hooks && "expand" in hooks ) {
			value = hooks.expand( value );
			delete props[ name ];

			// Not quite $.extend, this won't overwrite existing keys.
			// Reusing 'index' because we have the correct "name"
			for ( index in value ) {
				if ( !( index in props ) ) {
					props[ index ] = value[ index ];
					specialEasing[ index ] = easing;
				}
			}
		} else {
			specialEasing[ name ] = easing;
		}
	}
}

function Animation( elem, properties, options ) {
	var result,
		stopped,
		index = 0,
		length = Animation.prefilters.length,
		deferred = jQuery.Deferred().always( function() {

			// Don't match elem in the :animated selector
			delete tick.elem;
		} ),
		tick = function() {
			if ( stopped ) {
				return false;
			}
			var currentTime = fxNow || createFxNow(),
				remaining = Math.max( 0, animation.startTime + animation.duration - currentTime ),

				// Support: Android 2.3 only
				// Archaic crash bug won't allow us to use `1 - ( 0.5 || 0 )` (#12497)
				temp = remaining / animation.duration || 0,
				percent = 1 - temp,
				index = 0,
				length = animation.tweens.length;

			for ( ; index < length; index++ ) {
				animation.tweens[ index ].run( percent );
			}

			deferred.notifyWith( elem, [ animation, percent, remaining ] );

			// If there's more to do, yield
			if ( percent < 1 && length ) {
				return remaining;
			}

			// If this was an empty animation, synthesize a final progress notification
			if ( !length ) {
				deferred.notifyWith( elem, [ animation, 1, 0 ] );
			}

			// Resolve the animation and report its conclusion
			deferred.resolveWith( elem, [ animation ] );
			return false;
		},
		animation = deferred.promise( {
			elem: elem,
			props: jQuery.extend( {}, properties ),
			opts: jQuery.extend( true, {
				specialEasing: {},
				easing: jQuery.easing._default
			}, options ),
			originalProperties: properties,
			originalOptions: options,
			startTime: fxNow || createFxNow(),
			duration: options.duration,
			tweens: [],
			createTween: function( prop, end ) {
				var tween = jQuery.Tween( elem, animation.opts, prop, end,
						animation.opts.specialEasing[ prop ] || animation.opts.easing );
				animation.tweens.push( tween );
				return tween;
			},
			stop: function( gotoEnd ) {
				var index = 0,

					// If we are going to the end, we want to run all the tweens
					// otherwise we skip this part
					length = gotoEnd ? animation.tweens.length : 0;
				if ( stopped ) {
					return this;
				}
				stopped = true;
				for ( ; index < length; index++ ) {
					animation.tweens[ index ].run( 1 );
				}

				// Resolve when we played the last frame; otherwise, reject
				if ( gotoEnd ) {
					deferred.notifyWith( elem, [ animation, 1, 0 ] );
					deferred.resolveWith( elem, [ animation, gotoEnd ] );
				} else {
					deferred.rejectWith( elem, [ animation, gotoEnd ] );
				}
				return this;
			}
		} ),
		props = animation.props;

	propFilter( props, animation.opts.specialEasing );

	for ( ; index < length; index++ ) {
		result = Animation.prefilters[ index ].call( animation, elem, props, animation.opts );
		if ( result ) {
			if ( isFunction( result.stop ) ) {
				jQuery._queueHooks( animation.elem, animation.opts.queue ).stop =
					result.stop.bind( result );
			}
			return result;
		}
	}

	jQuery.map( props, createTween, animation );

	if ( isFunction( animation.opts.start ) ) {
		animation.opts.start.call( elem, animation );
	}

	// Attach callbacks from options
	animation
		.progress( animation.opts.progress )
		.done( animation.opts.done, animation.opts.complete )
		.fail( animation.opts.fail )
		.always( animation.opts.always );

	jQuery.fx.timer(
		jQuery.extend( tick, {
			elem: elem,
			anim: animation,
			queue: animation.opts.queue
		} )
	);

	return animation;
}

jQuery.Animation = jQuery.extend( Animation, {

	tweeners: {
		"*": [ function( prop, value ) {
			var tween = this.createTween( prop, value );
			adjustCSS( tween.elem, prop, rcssNum.exec( value ), tween );
			return tween;
		} ]
	},

	tweener: function( props, callback ) {
		if ( isFunction( props ) ) {
			callback = props;
			props = [ "*" ];
		} else {
			props = props.match( rnothtmlwhite );
		}

		var prop,
			index = 0,
			length = props.length;

		for ( ; index < length; index++ ) {
			prop = props[ index ];
			Animation.tweeners[ prop ] = Animation.tweeners[ prop ] || [];
			Animation.tweeners[ prop ].unshift( callback );
		}
	},

	prefilters: [ defaultPrefilter ],

	prefilter: function( callback, prepend ) {
		if ( prepend ) {
			Animation.prefilters.unshift( callback );
		} else {
			Animation.prefilters.push( callback );
		}
	}
} );

jQuery.speed = function( speed, easing, fn ) {
	var opt = speed && typeof speed === "object" ? jQuery.extend( {}, speed ) : {
		complete: fn || !fn && easing ||
			isFunction( speed ) && speed,
		duration: speed,
		easing: fn && easing || easing && !isFunction( easing ) && easing
	};

	// Go to the end state if fx are off
	if ( jQuery.fx.off ) {
		opt.duration = 0;

	} else {
		if ( typeof opt.duration !== "number" ) {
			if ( opt.duration in jQuery.fx.speeds ) {
				opt.duration = jQuery.fx.speeds[ opt.duration ];

			} else {
				opt.duration = jQuery.fx.speeds._default;
			}
		}
	}

	// Normalize opt.queue - true/undefined/null -> "fx"
	if ( opt.queue == null || opt.queue === true ) {
		opt.queue = "fx";
	}

	// Queueing
	opt.old = opt.complete;

	opt.complete = function() {
		if ( isFunction( opt.old ) ) {
			opt.old.call( this );
		}

		if ( opt.queue ) {
			jQuery.dequeue( this, opt.queue );
		}
	};

	return opt;
};

jQuery.fn.extend( {
	fadeTo: function( speed, to, easing, callback ) {

		// Show any hidden elements after setting opacity to 0
		return this.filter( isHiddenWithinTree ).css( "opacity", 0 ).show()

			// Animate to the value specified
			.end().animate( { opacity: to }, speed, easing, callback );
	},
	animate: function( prop, speed, easing, callback ) {
		var empty = jQuery.isEmptyObject( prop ),
			optall = jQuery.speed( speed, easing, callback ),
			doAnimation = function() {

				// Operate on a copy of prop so per-property easing won't be lost
				var anim = Animation( this, jQuery.extend( {}, prop ), optall );

				// Empty animations, or finishing resolves immediately
				if ( empty || dataPriv.get( this, "finish" ) ) {
					anim.stop( true );
				}
			};
			doAnimation.finish = doAnimation;

		return empty || optall.queue === false ?
			this.each( doAnimation ) :
			this.queue( optall.queue, doAnimation );
	},
	stop: function( type, clearQueue, gotoEnd ) {
		var stopQueue = function( hooks ) {
			var stop = hooks.stop;
			delete hooks.stop;
			stop( gotoEnd );
		};

		if ( typeof type !== "string" ) {
			gotoEnd = clearQueue;
			clearQueue = type;
			type = undefined;
		}
		if ( clearQueue ) {
			this.queue( type || "fx", [] );
		}

		return this.each( function() {
			var dequeue = true,
				index = type != null && type + "queueHooks",
				timers = jQuery.timers,
				data = dataPriv.get( this );

			if ( index ) {
				if ( data[ index ] && data[ index ].stop ) {
					stopQueue( data[ index ] );
				}
			} else {
				for ( index in data ) {
					if ( data[ index ] && data[ index ].stop && rrun.test( index ) ) {
						stopQueue( data[ index ] );
					}
				}
			}

			for ( index = timers.length; index--; ) {
				if ( timers[ index ].elem === this &&
					( type == null || timers[ index ].queue === type ) ) {

					timers[ index ].anim.stop( gotoEnd );
					dequeue = false;
					timers.splice( index, 1 );
				}
			}

			// Start the next in the queue if the last step wasn't forced.
			// Timers currently will call their complete callbacks, which
			// will dequeue but only if they were gotoEnd.
			if ( dequeue || !gotoEnd ) {
				jQuery.dequeue( this, type );
			}
		} );
	},
	finish: function( type ) {
		if ( type !== false ) {
			type = type || "fx";
		}
		return this.each( function() {
			var index,
				data = dataPriv.get( this ),
				queue = data[ type + "queue" ],
				hooks = data[ type + "queueHooks" ],
				timers = jQuery.timers,
				length = queue ? queue.length : 0;

			// Enable finishing flag on private data
			data.finish = true;

			// Empty the queue first
			jQuery.queue( this, type, [] );

			if ( hooks && hooks.stop ) {
				hooks.stop.call( this, true );
			}

			// Look for any active animations, and finish them
			for ( index = timers.length; index--; ) {
				if ( timers[ index ].elem === this && timers[ index ].queue === type ) {
					timers[ index ].anim.stop( true );
					timers.splice( index, 1 );
				}
			}

			// Look for any animations in the old queue and finish them
			for ( index = 0; index < length; index++ ) {
				if ( queue[ index ] && queue[ index ].finish ) {
					queue[ index ].finish.call( this );
				}
			}

			// Turn off finishing flag
			delete data.finish;
		} );
	}
} );

jQuery.each( [ "toggle", "show", "hide" ], function( _i, name ) {
	var cssFn = jQuery.fn[ name ];
	jQuery.fn[ name ] = function( speed, easing, callback ) {
		return speed == null || typeof speed === "boolean" ?
			cssFn.apply( this, arguments ) :
			this.animate( genFx( name, true ), speed, easing, callback );
	};
} );

// Generate shortcuts for custom animations
jQuery.each( {
	slideDown: genFx( "show" ),
	slideUp: genFx( "hide" ),
	slideToggle: genFx( "toggle" ),
	fadeIn: { opacity: "show" },
	fadeOut: { opacity: "hide" },
	fadeToggle: { opacity: "toggle" }
}, function( name, props ) {
	jQuery.fn[ name ] = function( speed, easing, callback ) {
		return this.animate( props, speed, easing, callback );
	};
} );

jQuery.timers = [];
jQuery.fx.tick = function() {
	var timer,
		i = 0,
		timers = jQuery.timers;

	fxNow = Date.now();

	for ( ; i < timers.length; i++ ) {
		timer = timers[ i ];

		// Run the timer and safely remove it when done (allowing for external removal)
		if ( !timer() && timers[ i ] === timer ) {
			timers.splice( i--, 1 );
		}
	}

	if ( !timers.length ) {
		jQuery.fx.stop();
	}
	fxNow = undefined;
};

jQuery.fx.timer = function( timer ) {
	jQuery.timers.push( timer );
	jQuery.fx.start();
};

jQuery.fx.interval = 13;
jQuery.fx.start = function() {
	if ( inProgress ) {
		return;
	}

	inProgress = true;
	schedule();
};

jQuery.fx.stop = function() {
	inProgress = null;
};

jQuery.fx.speeds = {
	slow: 600,
	fast: 200,

	// Default speed
	_default: 400
};


// Based off of the plugin by Clint Helfers, with permission.
// https://web.archive.org/web/20100324014747/http://blindsignals.com/index.php/2009/07/jquery-delay/
jQuery.fn.delay = function( time, type ) {
	time = jQuery.fx ? jQuery.fx.speeds[ time ] || time : time;
	type = type || "fx";

	return this.queue( type, function( next, hooks ) {
		var timeout = window.setTimeout( next, time );
		hooks.stop = function() {
			window.clearTimeout( timeout );
		};
	} );
};


( function() {
	var input = document.createElement( "input" ),
		select = document.createElement( "select" ),
		opt = select.appendChild( document.createElement( "option" ) );

	input.type = "checkbox";

	// Support: Android <=4.3 only
	// Default value for a checkbox should be "on"
	support.checkOn = input.value !== "";

	// Support: IE <=11 only
	// Must access selectedIndex to make default options select
	support.optSelected = opt.selected;

	// Support: IE <=11 only
	// An input loses its value after becoming a radio
	input = document.createElement( "input" );
	input.value = "t";
	input.type = "radio";
	support.radioValue = input.value === "t";
} )();


var boolHook,
	attrHandle = jQuery.expr.attrHandle;

jQuery.fn.extend( {
	attr: function( name, value ) {
		return access( this, jQuery.attr, name, value, arguments.length > 1 );
	},

	removeAttr: function( name ) {
		return this.each( function() {
			jQuery.removeAttr( this, name );
		} );
	}
} );

jQuery.extend( {
	attr: function( elem, name, value ) {
		var ret, hooks,
			nType = elem.nodeType;

		// Don't get/set attributes on text, comment and attribute nodes
		if ( nType === 3 || nType === 8 || nType === 2 ) {
			return;
		}

		// Fallback to prop when attributes are not supported
		if ( typeof elem.getAttribute === "undefined" ) {
			return jQuery.prop( elem, name, value );
		}

		// Attribute hooks are determined by the lowercase version
		// Grab necessary hook if one is defined
		if ( nType !== 1 || !jQuery.isXMLDoc( elem ) ) {
			hooks = jQuery.attrHooks[ name.toLowerCase() ] ||
				( jQuery.expr.match.bool.test( name ) ? boolHook : undefined );
		}

		if ( value !== undefined ) {
			if ( value === null ) {
				jQuery.removeAttr( elem, name );
				return;
			}

			if ( hooks && "set" in hooks &&
				( ret = hooks.set( elem, value, name ) ) !== undefined ) {
				return ret;
			}

			elem.setAttribute( name, value + "" );
			return value;
		}

		if ( hooks && "get" in hooks && ( ret = hooks.get( elem, name ) ) !== null ) {
			return ret;
		}

		ret = jQuery.find.attr( elem, name );

		// Non-existent attributes return null, we normalize to undefined
		return ret == null ? undefined : ret;
	},

	attrHooks: {
		type: {
			set: function( elem, value ) {
				if ( !support.radioValue && value === "radio" &&
					nodeName( elem, "input" ) ) {
					var val = elem.value;
					elem.setAttribute( "type", value );
					if ( val ) {
						elem.value = val;
					}
					return value;
				}
			}
		}
	},

	removeAttr: function( elem, value ) {
		var name,
			i = 0,

			// Attribute names can contain non-HTML whitespace characters
			// https://html.spec.whatwg.org/multipage/syntax.html#attributes-2
			attrNames = value && value.match( rnothtmlwhite );

		if ( attrNames && elem.nodeType === 1 ) {
			while ( ( name = attrNames[ i++ ] ) ) {
				elem.removeAttribute( name );
			}
		}
	}
} );

// Hooks for boolean attributes
boolHook = {
	set: function( elem, value, name ) {
		if ( value === false ) {

			// Remove boolean attributes when set to false
			jQuery.removeAttr( elem, name );
		} else {
			elem.setAttribute( name, name );
		}
		return name;
	}
};

jQuery.each( jQuery.expr.match.bool.source.match( /\w+/g ), function( _i, name ) {
	var getter = attrHandle[ name ] || jQuery.find.attr;

	attrHandle[ name ] = function( elem, name, isXML ) {
		var ret, handle,
			lowercaseName = name.toLowerCase();

		if ( !isXML ) {

			// Avoid an infinite loop by temporarily removing this function from the getter
			handle = attrHandle[ lowercaseName ];
			attrHandle[ lowercaseName ] = ret;
			ret = getter( elem, name, isXML ) != null ?
				lowercaseName :
				null;
			attrHandle[ lowercaseName ] = handle;
		}
		return ret;
	};
} );




var rfocusable = /^(?:input|select|textarea|button)$/i,
	rclickable = /^(?:a|area)$/i;

jQuery.fn.extend( {
	prop: function( name, value ) {
		return access( this, jQuery.prop, name, value, arguments.length > 1 );
	},

	removeProp: function( name ) {
		return this.each( function() {
			delete this[ jQuery.propFix[ name ] || name ];
		} );
	}
} );

jQuery.extend( {
	prop: function( elem, name, value ) {
		var ret, hooks,
			nType = elem.nodeType;

		// Don't get/set properties on text, comment and attribute nodes
		if ( nType === 3 || nType === 8 || nType === 2 ) {
			return;
		}

		if ( nType !== 1 || !jQuery.isXMLDoc( elem ) ) {

			// Fix name and attach hooks
			name = jQuery.propFix[ name ] || name;
			hooks = jQuery.propHooks[ name ];
		}

		if ( value !== undefined ) {
			if ( hooks && "set" in hooks &&
				( ret = hooks.set( elem, value, name ) ) !== undefined ) {
				return ret;
			}

			return ( elem[ name ] = value );
		}

		if ( hooks && "get" in hooks && ( ret = hooks.get( elem, name ) ) !== null ) {
			return ret;
		}

		return elem[ name ];
	},

	propHooks: {
		tabIndex: {
			get: function( elem ) {

				// Support: IE <=9 - 11 only
				// elem.tabIndex doesn't always return the
				// correct value when it hasn't been explicitly set
				// https://web.archive.org/web/20141116233347/http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-values-with-javascript/
				// Use proper attribute retrieval(#12072)
				var tabindex = jQuery.find.attr( elem, "tabindex" );

				if ( tabindex ) {
					return parseInt( tabindex, 10 );
				}

				if (
					rfocusable.test( elem.nodeName ) ||
					rclickable.test( elem.nodeName ) &&
					elem.href
				) {
					return 0;
				}

				return -1;
			}
		}
	},

	propFix: {
		"for": "htmlFor",
		"class": "className"
	}
} );

// Support: IE <=11 only
// Accessing the selectedIndex property
// forces the browser to respect setting selected
// on the option
// The getter ensures a default option is selected
// when in an optgroup
// eslint rule "no-unused-expressions" is disabled for this code
// since it considers such accessions noop
if ( !support.optSelected ) {
	jQuery.propHooks.selected = {
		get: function( elem ) {

			/* eslint no-unused-expressions: "off" */

			var parent = elem.parentNode;
			if ( parent && parent.parentNode ) {
				parent.parentNode.selectedIndex;
			}
			return null;
		},
		set: function( elem ) {

			/* eslint no-unused-expressions: "off" */

			var parent = elem.parentNode;
			if ( parent ) {
				parent.selectedIndex;

				if ( parent.parentNode ) {
					parent.parentNode.selectedIndex;
				}
			}
		}
	};
}

jQuery.each( [
	"tabIndex",
	"readOnly",
	"maxLength",
	"cellSpacing",
	"cellPadding",
	"rowSpan",
	"colSpan",
	"useMap",
	"frameBorder",
	"contentEditable"
], function() {
	jQuery.propFix[ this.toLowerCase() ] = this;
} );




	// Strip and collapse whitespace according to HTML spec
	// https://infra.spec.whatwg.org/#strip-and-collapse-ascii-whitespace
	function stripAndCollapse( value ) {
		var tokens = value.match( rnothtmlwhite ) || [];
		return tokens.join( " " );
	}


function getClass( elem ) {
	return elem.getAttribute && elem.getAttribute( "class" ) || "";
}

function classesToArray( value ) {
	if ( Array.isArray( value ) ) {
		return value;
	}
	if ( typeof value === "string" ) {
		return value.match( rnothtmlwhite ) || [];
	}
	return [];
}

jQuery.fn.extend( {
	addClass: function( value ) {
		var classes, elem, cur, curValue, clazz, j, finalValue,
			i = 0;

		if ( isFunction( value ) ) {
			return this.each( function( j ) {
				jQuery( this ).addClass( value.call( this, j, getClass( this ) ) );
			} );
		}

		classes = classesToArray( value );

		if ( classes.length ) {
			while ( ( elem = this[ i++ ] ) ) {
				curValue = getClass( elem );
				cur = elem.nodeType === 1 && ( " " + stripAndCollapse( curValue ) + " " );

				if ( cur ) {
					j = 0;
					while ( ( clazz = classes[ j++ ] ) ) {
						if ( cur.indexOf( " " + clazz + " " ) < 0 ) {
							cur += clazz + " ";
						}
					}

					// Only assign if different to avoid unneeded rendering.
					finalValue = stripAndCollapse( cur );
					if ( curValue !== finalValue ) {
						elem.setAttribute( "class", finalValue );
					}
				}
			}
		}

		return this;
	},

	removeClass: function( value ) {
		var classes, elem, cur, curValue, clazz, j, finalValue,
			i = 0;

		if ( isFunction( value ) ) {
			return this.each( function( j ) {
				jQuery( this ).removeClass( value.call( this, j, getClass( this ) ) );
			} );
		}

		if ( !arguments.length ) {
			return this.attr( "class", "" );
		}

		classes = classesToArray( value );

		if ( classes.length ) {
			while ( ( elem = this[ i++ ] ) ) {
				curValue = getClass( elem );

				// This expression is here for better compressibility (see addClass)
				cur = elem.nodeType === 1 && ( " " + stripAndCollapse( curValue ) + " " );

				if ( cur ) {
					j = 0;
					while ( ( clazz = classes[ j++ ] ) ) {

						// Remove *all* instances
						while ( cur.indexOf( " " + clazz + " " ) > -1 ) {
							cur = cur.replace( " " + clazz + " ", " " );
						}
					}

					// Only assign if different to avoid unneeded rendering.
					finalValue = stripAndCollapse( cur );
					if ( curValue !== finalValue ) {
						elem.setAttribute( "class", finalValue );
					}
				}
			}
		}

		return this;
	},

	toggleClass: function( value, stateVal ) {
		var type = typeof value,
			isValidValue = type === "string" || Array.isArray( value );

		if ( typeof stateVal === "boolean" && isValidValue ) {
			return stateVal ? this.addClass( value ) : this.removeClass( value );
		}

		if ( isFunction( value ) ) {
			return this.each( function( i ) {
				jQuery( this ).toggleClass(
					value.call( this, i, getClass( this ), stateVal ),
					stateVal
				);
			} );
		}

		return this.each( function() {
			var className, i, self, classNames;

			if ( isValidValue ) {

				// Toggle individual class names
				i = 0;
				self = jQuery( this );
				classNames = classesToArray( value );

				while ( ( className = classNames[ i++ ] ) ) {

					// Check each className given, space separated list
					if ( self.hasClass( className ) ) {
						self.removeClass( className );
					} else {
						self.addClass( className );
					}
				}

			// Toggle whole class name
			} else if ( value === undefined || type === "boolean" ) {
				className = getClass( this );
				if ( className ) {

					// Store className if set
					dataPriv.set( this, "__className__", className );
				}

				// If the element has a class name or if we're passed `false`,
				// then remove the whole classname (if there was one, the above saved it).
				// Otherwise bring back whatever was previously saved (if anything),
				// falling back to the empty string if nothing was stored.
				if ( this.setAttribute ) {
					this.setAttribute( "class",
						className || value === false ?
						"" :
						dataPriv.get( this, "__className__" ) || ""
					);
				}
			}
		} );
	},

	hasClass: function( selector ) {
		var className, elem,
			i = 0;

		className = " " + selector + " ";
		while ( ( elem = this[ i++ ] ) ) {
			if ( elem.nodeType === 1 &&
				( " " + stripAndCollapse( getClass( elem ) ) + " " ).indexOf( className ) > -1 ) {
					return true;
			}
		}

		return false;
	}
} );




var rreturn = /\r/g;

jQuery.fn.extend( {
	val: function( value ) {
		var hooks, ret, valueIsFunction,
			elem = this[ 0 ];

		if ( !arguments.length ) {
			if ( elem ) {
				hooks = jQuery.valHooks[ elem.type ] ||
					jQuery.valHooks[ elem.nodeName.toLowerCase() ];

				if ( hooks &&
					"get" in hooks &&
					( ret = hooks.get( elem, "value" ) ) !== undefined
				) {
					return ret;
				}

				ret = elem.value;

				// Handle most common string cases
				if ( typeof ret === "string" ) {
					return ret.replace( rreturn, "" );
				}

				// Handle cases where value is null/undef or number
				return ret == null ? "" : ret;
			}

			return;
		}

		valueIsFunction = isFunction( value );

		return this.each( function( i ) {
			var val;

			if ( this.nodeType !== 1 ) {
				return;
			}

			if ( valueIsFunction ) {
				val = value.call( this, i, jQuery( this ).val() );
			} else {
				val = value;
			}

			// Treat null/undefined as ""; convert numbers to string
			if ( val == null ) {
				val = "";

			} else if ( typeof val === "number" ) {
				val += "";

			} else if ( Array.isArray( val ) ) {
				val = jQuery.map( val, function( value ) {
					return value == null ? "" : value + "";
				} );
			}

			hooks = jQuery.valHooks[ this.type ] || jQuery.valHooks[ this.nodeName.toLowerCase() ];

			// If set returns undefined, fall back to normal setting
			if ( !hooks || !( "set" in hooks ) || hooks.set( this, val, "value" ) === undefined ) {
				this.value = val;
			}
		} );
	}
} );

jQuery.extend( {
	valHooks: {
		option: {
			get: function( elem ) {

				var val = jQuery.find.attr( elem, "value" );
				return val != null ?
					val :

					// Support: IE <=10 - 11 only
					// option.text throws exceptions (#14686, #14858)
					// Strip and collapse whitespace
					// https://html.spec.whatwg.org/#strip-and-collapse-whitespace
					stripAndCollapse( jQuery.text( elem ) );
			}
		},
		select: {
			get: function( elem ) {
				var value, option, i,
					options = elem.options,
					index = elem.selectedIndex,
					one = elem.type === "select-one",
					values = one ? null : [],
					max = one ? index + 1 : options.length;

				if ( index < 0 ) {
					i = max;

				} else {
					i = one ? index : 0;
				}

				// Loop through all the selected options
				for ( ; i < max; i++ ) {
					option = options[ i ];

					// Support: IE <=9 only
					// IE8-9 doesn't update selected after form reset (#2551)
					if ( ( option.selected || i === index ) &&

							// Don't return options that are disabled or in a disabled optgroup
							!option.disabled &&
							( !option.parentNode.disabled ||
								!nodeName( option.parentNode, "optgroup" ) ) ) {

						// Get the specific value for the option
						value = jQuery( option ).val();

						// We don't need an array for one selects
						if ( one ) {
							return value;
						}

						// Multi-Selects return an array
						values.push( value );
					}
				}

				return values;
			},

			set: function( elem, value ) {
				var optionSet, option,
					options = elem.options,
					values = jQuery.makeArray( value ),
					i = options.length;

				while ( i-- ) {
					option = options[ i ];

					/* eslint-disable no-cond-assign */

					if ( option.selected =
						jQuery.inArray( jQuery.valHooks.option.get( option ), values ) > -1
					) {
						optionSet = true;
					}

					/* eslint-enable no-cond-assign */
				}

				// Force browsers to behave consistently when non-matching value is set
				if ( !optionSet ) {
					elem.selectedIndex = -1;
				}
				return values;
			}
		}
	}
} );

// Radios and checkboxes getter/setter
jQuery.each( [ "radio", "checkbox" ], function() {
	jQuery.valHooks[ this ] = {
		set: function( elem, value ) {
			if ( Array.isArray( value ) ) {
				return ( elem.checked = jQuery.inArray( jQuery( elem ).val(), value ) > -1 );
			}
		}
	};
	if ( !support.checkOn ) {
		jQuery.valHooks[ this ].get = function( elem ) {
			return elem.getAttribute( "value" ) === null ? "on" : elem.value;
		};
	}
} );




// Return jQuery for attributes-only inclusion


support.focusin = "onfocusin" in window;


var rfocusMorph = /^(?:focusinfocus|focusoutblur)$/,
	stopPropagationCallback = function( e ) {
		e.stopPropagation();
	};

jQuery.extend( jQuery.event, {

	trigger: function( event, data, elem, onlyHandlers ) {

		var i, cur, tmp, bubbleType, ontype, handle, special, lastElement,
			eventPath = [ elem || document ],
			type = hasOwn.call( event, "type" ) ? event.type : event,
			namespaces = hasOwn.call( event, "namespace" ) ? event.namespace.split( "." ) : [];

		cur = lastElement = tmp = elem = elem || document;

		// Don't do events on text and comment nodes
		if ( elem.nodeType === 3 || elem.nodeType === 8 ) {
			return;
		}

		// focus/blur morphs to focusin/out; ensure we're not firing them right now
		if ( rfocusMorph.test( type + jQuery.event.triggered ) ) {
			return;
		}

		if ( type.indexOf( "." ) > -1 ) {

			// Namespaced trigger; create a regexp to match event type in handle()
			namespaces = type.split( "." );
			type = namespaces.shift();
			namespaces.sort();
		}
		ontype = type.indexOf( ":" ) < 0 && "on" + type;

		// Caller can pass in a jQuery.Event object, Object, or just an event type string
		event = event[ jQuery.expando ] ?
			event :
			new jQuery.Event( type, typeof event === "object" && event );

		// Trigger bitmask: & 1 for native handlers; & 2 for jQuery (always true)
		event.isTrigger = onlyHandlers ? 2 : 3;
		event.namespace = namespaces.join( "." );
		event.rnamespace = event.namespace ?
			new RegExp( "(^|\\.)" + namespaces.join( "\\.(?:.*\\.|)" ) + "(\\.|$)" ) :
			null;

		// Clean up the event in case it is being reused
		event.result = undefined;
		if ( !event.target ) {
			event.target = elem;
		}

		// Clone any incoming data and prepend the event, creating the handler arg list
		data = data == null ?
			[ event ] :
			jQuery.makeArray( data, [ event ] );

		// Allow special events to draw outside the lines
		special = jQuery.event.special[ type ] || {};
		if ( !onlyHandlers && special.trigger && special.trigger.apply( elem, data ) === false ) {
			return;
		}

		// Determine event propagation path in advance, per W3C events spec (#9951)
		// Bubble up to document, then to window; watch for a global ownerDocument var (#9724)
		if ( !onlyHandlers && !special.noBubble && !isWindow( elem ) ) {

			bubbleType = special.delegateType || type;
			if ( !rfocusMorph.test( bubbleType + type ) ) {
				cur = cur.parentNode;
			}
			for ( ; cur; cur = cur.parentNode ) {
				eventPath.push( cur );
				tmp = cur;
			}

			// Only add window if we got to document (e.g., not plain obj or detached DOM)
			if ( tmp === ( elem.ownerDocument || document ) ) {
				eventPath.push( tmp.defaultView || tmp.parentWindow || window );
			}
		}

		// Fire handlers on the event path
		i = 0;
		while ( ( cur = eventPath[ i++ ] ) && !event.isPropagationStopped() ) {
			lastElement = cur;
			event.type = i > 1 ?
				bubbleType :
				special.bindType || type;

			// jQuery handler
			handle = (
					dataPriv.get( cur, "events" ) || Object.create( null )
				)[ event.type ] &&
				dataPriv.get( cur, "handle" );
			if ( handle ) {
				handle.apply( cur, data );
			}

			// Native handler
			handle = ontype && cur[ ontype ];
			if ( handle && handle.apply && acceptData( cur ) ) {
				event.result = handle.apply( cur, data );
				if ( event.result === false ) {
					event.preventDefault();
				}
			}
		}
		event.type = type;

		// If nobody prevented the default action, do it now
		if ( !onlyHandlers && !event.isDefaultPrevented() ) {

			if ( ( !special._default ||
				special._default.apply( eventPath.pop(), data ) === false ) &&
				acceptData( elem ) ) {

				// Call a native DOM method on the target with the same name as the event.
				// Don't do default actions on window, that's where global variables be (#6170)
				if ( ontype && isFunction( elem[ type ] ) && !isWindow( elem ) ) {

					// Don't re-trigger an onFOO event when we call its FOO() method
					tmp = elem[ ontype ];

					if ( tmp ) {
						elem[ ontype ] = null;
					}

					// Prevent re-triggering of the same event, since we already bubbled it above
					jQuery.event.triggered = type;

					if ( event.isPropagationStopped() ) {
						lastElement.addEventListener( type, stopPropagationCallback );
					}

					elem[ type ]();

					if ( event.isPropagationStopped() ) {
						lastElement.removeEventListener( type, stopPropagationCallback );
					}

					jQuery.event.triggered = undefined;

					if ( tmp ) {
						elem[ ontype ] = tmp;
					}
				}
			}
		}

		return event.result;
	},

	// Piggyback on a donor event to simulate a different one
	// Used only for `focus(in | out)` events
	simulate: function( type, elem, event ) {
		var e = jQuery.extend(
			new jQuery.Event(),
			event,
			{
				type: type,
				isSimulated: true
			}
		);

		jQuery.event.trigger( e, null, elem );
	}

} );

jQuery.fn.extend( {

	trigger: function( type, data ) {
		return this.each( function() {
			jQuery.event.trigger( type, data, this );
		} );
	},
	triggerHandler: function( type, data ) {
		var elem = this[ 0 ];
		if ( elem ) {
			return jQuery.event.trigger( type, data, elem, true );
		}
	}
} );


// Support: Firefox <=44
// Firefox doesn't have focus(in | out) events
// Related ticket - https://bugzilla.mozilla.org/show_bug.cgi?id=687787
//
// Support: Chrome <=48 - 49, Safari <=9.0 - 9.1
// focus(in | out) events fire after focus & blur events,
// which is spec violation - http://www.w3.org/TR/DOM-Level-3-Events/#events-focusevent-event-order
// Related ticket - https://bugs.chromium.org/p/chromium/issues/detail?id=449857
if ( !support.focusin ) {
	jQuery.each( { focus: "focusin", blur: "focusout" }, function( orig, fix ) {

		// Attach a single capturing handler on the document while someone wants focusin/focusout
		var handler = function( event ) {
			jQuery.event.simulate( fix, event.target, jQuery.event.fix( event ) );
		};

		jQuery.event.special[ fix ] = {
			setup: function() {

				// Handle: regular nodes (via `this.ownerDocument`), window
				// (via `this.document`) & document (via `this`).
				var doc = this.ownerDocument || this.document || this,
					attaches = dataPriv.access( doc, fix );

				if ( !attaches ) {
					doc.addEventListener( orig, handler, true );
				}
				dataPriv.access( doc, fix, ( attaches || 0 ) + 1 );
			},
			teardown: function() {
				var doc = this.ownerDocument || this.document || this,
					attaches = dataPriv.access( doc, fix ) - 1;

				if ( !attaches ) {
					doc.removeEventListener( orig, handler, true );
					dataPriv.remove( doc, fix );

				} else {
					dataPriv.access( doc, fix, attaches );
				}
			}
		};
	} );
}
var location = window.location;

var nonce = { guid: Date.now() };

var rquery = ( /\?/ );



// Cross-browser xml parsing
jQuery.parseXML = function( data ) {
	var xml;
	if ( !data || typeof data !== "string" ) {
		return null;
	}

	// Support: IE 9 - 11 only
	// IE throws on parseFromString with invalid input.
	try {
		xml = ( new window.DOMParser() ).parseFromString( data, "text/xml" );
	} catch ( e ) {
		xml = undefined;
	}

	if ( !xml || xml.getElementsByTagName( "parsererror" ).length ) {
		jQuery.error( "Invalid XML: " + data );
	}
	return xml;
};


var
	rbracket = /\[\]$/,
	rCRLF = /\r?\n/g,
	rsubmitterTypes = /^(?:submit|button|image|reset|file)$/i,
	rsubmittable = /^(?:input|select|textarea|keygen)/i;

function buildParams( prefix, obj, traditional, add ) {
	var name;

	if ( Array.isArray( obj ) ) {

		// Serialize array item.
		jQuery.each( obj, function( i, v ) {
			if ( traditional || rbracket.test( prefix ) ) {

				// Treat each array item as a scalar.
				add( prefix, v );

			} else {

				// Item is non-scalar (array or object), encode its numeric index.
				buildParams(
					prefix + "[" + ( typeof v === "object" && v != null ? i : "" ) + "]",
					v,
					traditional,
					add
				);
			}
		} );

	} else if ( !traditional && toType( obj ) === "object" ) {

		// Serialize object item.
		for ( name in obj ) {
			buildParams( prefix + "[" + name + "]", obj[ name ], traditional, add );
		}

	} else {

		// Serialize scalar item.
		add( prefix, obj );
	}
}

// Serialize an array of form elements or a set of
// key/values into a query string
jQuery.param = function( a, traditional ) {
	var prefix,
		s = [],
		add = function( key, valueOrFunction ) {

			// If value is a function, invoke it and use its return value
			var value = isFunction( valueOrFunction ) ?
				valueOrFunction() :
				valueOrFunction;

			s[ s.length ] = encodeURIComponent( key ) + "=" +
				encodeURIComponent( value == null ? "" : value );
		};

	if ( a == null ) {
		return "";
	}

	// If an array was passed in, assume that it is an array of form elements.
	if ( Array.isArray( a ) || ( a.jquery && !jQuery.isPlainObject( a ) ) ) {

		// Serialize the form elements
		jQuery.each( a, function() {
			add( this.name, this.value );
		} );

	} else {

		// If traditional, encode the "old" way (the way 1.3.2 or older
		// did it), otherwise encode params recursively.
		for ( prefix in a ) {
			buildParams( prefix, a[ prefix ], traditional, add );
		}
	}

	// Return the resulting serialization
	return s.join( "&" );
};

jQuery.fn.extend( {
	serialize: function() {
		return jQuery.param( this.serializeArray() );
	},
	serializeArray: function() {
		return this.map( function() {

			// Can add propHook for "elements" to filter or add form elements
			var elements = jQuery.prop( this, "elements" );
			return elements ? jQuery.makeArray( elements ) : this;
		} )
		.filter( function() {
			var type = this.type;

			// Use .is( ":disabled" ) so that fieldset[disabled] works
			return this.name && !jQuery( this ).is( ":disabled" ) &&
				rsubmittable.test( this.nodeName ) && !rsubmitterTypes.test( type ) &&
				( this.checked || !rcheckableType.test( type ) );
		} )
		.map( function( _i, elem ) {
			var val = jQuery( this ).val();

			if ( val == null ) {
				return null;
			}

			if ( Array.isArray( val ) ) {
				return jQuery.map( val, function( val ) {
					return { name: elem.name, value: val.replace( rCRLF, "\r\n" ) };
				} );
			}

			return { name: elem.name, value: val.replace( rCRLF, "\r\n" ) };
		} ).get();
	}
} );


var
	r20 = /%20/g,
	rhash = /#.*$/,
	rantiCache = /([?&])_=[^&]*/,
	rheaders = /^(.*?):[ \t]*([^\r\n]*)$/mg,

	// #7653, #8125, #8152: local protocol detection
	rlocalProtocol = /^(?:about|app|app-storage|.+-extension|file|res|widget):$/,
	rnoContent = /^(?:GET|HEAD)$/,
	rprotocol = /^\/\//,

	/* Prefilters
	 * 1) They are useful to introduce custom dataTypes (see ajax/jsonp.js for an example)
	 * 2) These are called:
	 *    - BEFORE asking for a transport
	 *    - AFTER param serialization (s.data is a string if s.processData is true)
	 * 3) key is the dataType
	 * 4) the catchall symbol "*" can be used
	 * 5) execution will start with transport dataType and THEN continue down to "*" if needed
	 */
	prefilters = {},

	/* Transports bindings
	 * 1) key is the dataType
	 * 2) the catchall symbol "*" can be used
	 * 3) selection will start with transport dataType and THEN go to "*" if needed
	 */
	transports = {},

	// Avoid comment-prolog char sequence (#10098); must appease lint and evade compression
	allTypes = "*/".concat( "*" ),

	// Anchor tag for parsing the document origin
	originAnchor = document.createElement( "a" );
	originAnchor.href = location.href;

// Base "constructor" for jQuery.ajaxPrefilter and jQuery.ajaxTransport
function addToPrefiltersOrTransports( structure ) {

	// dataTypeExpression is optional and defaults to "*"
	return function( dataTypeExpression, func ) {

		if ( typeof dataTypeExpression !== "string" ) {
			func = dataTypeExpression;
			dataTypeExpression = "*";
		}

		var dataType,
			i = 0,
			dataTypes = dataTypeExpression.toLowerCase().match( rnothtmlwhite ) || [];

		if ( isFunction( func ) ) {

			// For each dataType in the dataTypeExpression
			while ( ( dataType = dataTypes[ i++ ] ) ) {

				// Prepend if requested
				if ( dataType[ 0 ] === "+" ) {
					dataType = dataType.slice( 1 ) || "*";
					( structure[ dataType ] = structure[ dataType ] || [] ).unshift( func );

				// Otherwise append
				} else {
					( structure[ dataType ] = structure[ dataType ] || [] ).push( func );
				}
			}
		}
	};
}

// Base inspection function for prefilters and transports
function inspectPrefiltersOrTransports( structure, options, originalOptions, jqXHR ) {

	var inspected = {},
		seekingTransport = ( structure === transports );

	function inspect( dataType ) {
		var selected;
		inspected[ dataType ] = true;
		jQuery.each( structure[ dataType ] || [], function( _, prefilterOrFactory ) {
			var dataTypeOrTransport = prefilterOrFactory( options, originalOptions, jqXHR );
			if ( typeof dataTypeOrTransport === "string" &&
				!seekingTransport && !inspected[ dataTypeOrTransport ] ) {

				options.dataTypes.unshift( dataTypeOrTransport );
				inspect( dataTypeOrTransport );
				return false;
			} else if ( seekingTransport ) {
				return !( selected = dataTypeOrTransport );
			}
		} );
		return selected;
	}

	return inspect( options.dataTypes[ 0 ] ) || !inspected[ "*" ] && inspect( "*" );
}

// A special extend for ajax options
// that takes "flat" options (not to be deep extended)
// Fixes #9887
function ajaxExtend( target, src ) {
	var key, deep,
		flatOptions = jQuery.ajaxSettings.flatOptions || {};

	for ( key in src ) {
		if ( src[ key ] !== undefined ) {
			( flatOptions[ key ] ? target : ( deep || ( deep = {} ) ) )[ key ] = src[ key ];
		}
	}
	if ( deep ) {
		jQuery.extend( true, target, deep );
	}

	return target;
}

/* Handles responses to an ajax request:
 * - finds the right dataType (mediates between content-type and expected dataType)
 * - returns the corresponding response
 */
function ajaxHandleResponses( s, jqXHR, responses ) {

	var ct, type, finalDataType, firstDataType,
		contents = s.contents,
		dataTypes = s.dataTypes;

	// Remove auto dataType and get content-type in the process
	while ( dataTypes[ 0 ] === "*" ) {
		dataTypes.shift();
		if ( ct === undefined ) {
			ct = s.mimeType || jqXHR.getResponseHeader( "Content-Type" );
		}
	}

	// Check if we're dealing with a known content-type
	if ( ct ) {
		for ( type in contents ) {
			if ( contents[ type ] && contents[ type ].test( ct ) ) {
				dataTypes.unshift( type );
				break;
			}
		}
	}

	// Check to see if we have a response for the expected dataType
	if ( dataTypes[ 0 ] in responses ) {
		finalDataType = dataTypes[ 0 ];
	} else {

		// Try convertible dataTypes
		for ( type in responses ) {
			if ( !dataTypes[ 0 ] || s.converters[ type + " " + dataTypes[ 0 ] ] ) {
				finalDataType = type;
				break;
			}
			if ( !firstDataType ) {
				firstDataType = type;
			}
		}

		// Or just use first one
		finalDataType = finalDataType || firstDataType;
	}

	// If we found a dataType
	// We add the dataType to the list if needed
	// and return the corresponding response
	if ( finalDataType ) {
		if ( finalDataType !== dataTypes[ 0 ] ) {
			dataTypes.unshift( finalDataType );
		}
		return responses[ finalDataType ];
	}
}

/* Chain conversions given the request and the original response
 * Also sets the responseXXX fields on the jqXHR instance
 */
function ajaxConvert( s, response, jqXHR, isSuccess ) {
	var conv2, current, conv, tmp, prev,
		converters = {},

		// Work with a copy of dataTypes in case we need to modify it for conversion
		dataTypes = s.dataTypes.slice();

	// Create converters map with lowercased keys
	if ( dataTypes[ 1 ] ) {
		for ( conv in s.converters ) {
			converters[ conv.toLowerCase() ] = s.converters[ conv ];
		}
	}

	current = dataTypes.shift();

	// Convert to each sequential dataType
	while ( current ) {

		if ( s.responseFields[ current ] ) {
			jqXHR[ s.responseFields[ current ] ] = response;
		}

		// Apply the dataFilter if provided
		if ( !prev && isSuccess && s.dataFilter ) {
			response = s.dataFilter( response, s.dataType );
		}

		prev = current;
		current = dataTypes.shift();

		if ( current ) {

			// There's only work to do if current dataType is non-auto
			if ( current === "*" ) {

				current = prev;

			// Convert response if prev dataType is non-auto and differs from current
			} else if ( prev !== "*" && prev !== current ) {

				// Seek a direct converter
				conv = converters[ prev + " " + current ] || converters[ "* " + current ];

				// If none found, seek a pair
				if ( !conv ) {
					for ( conv2 in converters ) {

						// If conv2 outputs current
						tmp = conv2.split( " " );
						if ( tmp[ 1 ] === current ) {

							// If prev can be converted to accepted input
							conv = converters[ prev + " " + tmp[ 0 ] ] ||
								converters[ "* " + tmp[ 0 ] ];
							if ( conv ) {

								// Condense equivalence converters
								if ( conv === true ) {
									conv = converters[ conv2 ];

								// Otherwise, insert the intermediate dataType
								} else if ( converters[ conv2 ] !== true ) {
									current = tmp[ 0 ];
									dataTypes.unshift( tmp[ 1 ] );
								}
								break;
							}
						}
					}
				}

				// Apply converter (if not an equivalence)
				if ( conv !== true ) {

					// Unless errors are allowed to bubble, catch and return them
					if ( conv && s.throws ) {
						response = conv( response );
					} else {
						try {
							response = conv( response );
						} catch ( e ) {
							return {
								state: "parsererror",
								error: conv ? e : "No conversion from " + prev + " to " + current
							};
						}
					}
				}
			}
		}
	}

	return { state: "success", data: response };
}

jQuery.extend( {

	// Counter for holding the number of active queries
	active: 0,

	// Last-Modified header cache for next request
	lastModified: {},
	etag: {},

	ajaxSettings: {
		url: location.href,
		type: "GET",
		isLocal: rlocalProtocol.test( location.protocol ),
		global: true,
		processData: true,
		async: true,
		contentType: "application/x-www-form-urlencoded; charset=UTF-8",

		/*
		timeout: 0,
		data: null,
		dataType: null,
		username: null,
		password: null,
		cache: null,
		throws: false,
		traditional: false,
		headers: {},
		*/

		accepts: {
			"*": allTypes,
			text: "text/plain",
			html: "text/html",
			xml: "application/xml, text/xml",
			json: "application/json, text/javascript"
		},

		contents: {
			xml: /\bxml\b/,
			html: /\bhtml/,
			json: /\bjson\b/
		},

		responseFields: {
			xml: "responseXML",
			text: "responseText",
			json: "responseJSON"
		},

		// Data converters
		// Keys separate source (or catchall "*") and destination types with a single space
		converters: {

			// Convert anything to text
			"* text": String,

			// Text to html (true = no transformation)
			"text html": true,

			// Evaluate text as a json expression
			"text json": JSON.parse,

			// Parse text as xml
			"text xml": jQuery.parseXML
		},

		// For options that shouldn't be deep extended:
		// you can add your own custom options here if
		// and when you create one that shouldn't be
		// deep extended (see ajaxExtend)
		flatOptions: {
			url: true,
			context: true
		}
	},

	// Creates a full fledged settings object into target
	// with both ajaxSettings and settings fields.
	// If target is omitted, writes into ajaxSettings.
	ajaxSetup: function( target, settings ) {
		return settings ?

			// Building a settings object
			ajaxExtend( ajaxExtend( target, jQuery.ajaxSettings ), settings ) :

			// Extending ajaxSettings
			ajaxExtend( jQuery.ajaxSettings, target );
	},

	ajaxPrefilter: addToPrefiltersOrTransports( prefilters ),
	ajaxTransport: addToPrefiltersOrTransports( transports ),

	// Main method
	ajax: function( url, options ) {

		// If url is an object, simulate pre-1.5 signature
		if ( typeof url === "object" ) {
			options = url;
			url = undefined;
		}

		// Force options to be an object
		options = options || {};

		var transport,

			// URL without anti-cache param
			cacheURL,

			// Response headers
			responseHeadersString,
			responseHeaders,

			// timeout handle
			timeoutTimer,

			// Url cleanup var
			urlAnchor,

			// Request state (becomes false upon send and true upon completion)
			completed,

			// To know if global events are to be dispatched
			fireGlobals,

			// Loop variable
			i,

			// uncached part of the url
			uncached,

			// Create the final options object
			s = jQuery.ajaxSetup( {}, options ),

			// Callbacks context
			callbackContext = s.context || s,

			// Context for global events is callbackContext if it is a DOM node or jQuery collection
			globalEventContext = s.context &&
				( callbackContext.nodeType || callbackContext.jquery ) ?
					jQuery( callbackContext ) :
					jQuery.event,

			// Deferreds
			deferred = jQuery.Deferred(),
			completeDeferred = jQuery.Callbacks( "once memory" ),

			// Status-dependent callbacks
			statusCode = s.statusCode || {},

			// Headers (they are sent all at once)
			requestHeaders = {},
			requestHeadersNames = {},

			// Default abort message
			strAbort = "canceled",

			// Fake xhr
			jqXHR = {
				readyState: 0,

				// Builds headers hashtable if needed
				getResponseHeader: function( key ) {
					var match;
					if ( completed ) {
						if ( !responseHeaders ) {
							responseHeaders = {};
							while ( ( match = rheaders.exec( responseHeadersString ) ) ) {
								responseHeaders[ match[ 1 ].toLowerCase() + " " ] =
									( responseHeaders[ match[ 1 ].toLowerCase() + " " ] || [] )
										.concat( match[ 2 ] );
							}
						}
						match = responseHeaders[ key.toLowerCase() + " " ];
					}
					return match == null ? null : match.join( ", " );
				},

				// Raw string
				getAllResponseHeaders: function() {
					return completed ? responseHeadersString : null;
				},

				// Caches the header
				setRequestHeader: function( name, value ) {
					if ( completed == null ) {
						name = requestHeadersNames[ name.toLowerCase() ] =
							requestHeadersNames[ name.toLowerCase() ] || name;
						requestHeaders[ name ] = value;
					}
					return this;
				},

				// Overrides response content-type header
				overrideMimeType: function( type ) {
					if ( completed == null ) {
						s.mimeType = type;
					}
					return this;
				},

				// Status-dependent callbacks
				statusCode: function( map ) {
					var code;
					if ( map ) {
						if ( completed ) {

							// Execute the appropriate callbacks
							jqXHR.always( map[ jqXHR.status ] );
						} else {

							// Lazy-add the new callbacks in a way that preserves old ones
							for ( code in map ) {
								statusCode[ code ] = [ statusCode[ code ], map[ code ] ];
							}
						}
					}
					return this;
				},

				// Cancel the request
				abort: function( statusText ) {
					var finalText = statusText || strAbort;
					if ( transport ) {
						transport.abort( finalText );
					}
					done( 0, finalText );
					return this;
				}
			};

		// Attach deferreds
		deferred.promise( jqXHR );

		// Add protocol if not provided (prefilters might expect it)
		// Handle falsy url in the settings object (#10093: consistency with old signature)
		// We also use the url parameter if available
		s.url = ( ( url || s.url || location.href ) + "" )
			.replace( rprotocol, location.protocol + "//" );

		// Alias method option to type as per ticket #12004
		s.type = options.method || options.type || s.method || s.type;

		// Extract dataTypes list
		s.dataTypes = ( s.dataType || "*" ).toLowerCase().match( rnothtmlwhite ) || [ "" ];

		// A cross-domain request is in order when the origin doesn't match the current origin.
		if ( s.crossDomain == null ) {
			urlAnchor = document.createElement( "a" );

			// Support: IE <=8 - 11, Edge 12 - 15
			// IE throws exception on accessing the href property if url is malformed,
			// e.g. http://example.com:80x/
			try {
				urlAnchor.href = s.url;

				// Support: IE <=8 - 11 only
				// Anchor's host property isn't correctly set when s.url is relative
				urlAnchor.href = urlAnchor.href;
				s.crossDomain = originAnchor.protocol + "//" + originAnchor.host !==
					urlAnchor.protocol + "//" + urlAnchor.host;
			} catch ( e ) {

				// If there is an error parsing the URL, assume it is crossDomain,
				// it can be rejected by the transport if it is invalid
				s.crossDomain = true;
			}
		}

		// Convert data if not already a string
		if ( s.data && s.processData && typeof s.data !== "string" ) {
			s.data = jQuery.param( s.data, s.traditional );
		}

		// Apply prefilters
		inspectPrefiltersOrTransports( prefilters, s, options, jqXHR );

		// If request was aborted inside a prefilter, stop there
		if ( completed ) {
			return jqXHR;
		}

		// We can fire global events as of now if asked to
		// Don't fire events if jQuery.event is undefined in an AMD-usage scenario (#15118)
		fireGlobals = jQuery.event && s.global;

		// Watch for a new set of requests
		if ( fireGlobals && jQuery.active++ === 0 ) {
			jQuery.event.trigger( "ajaxStart" );
		}

		// Uppercase the type
		s.type = s.type.toUpperCase();

		// Determine if request has content
		s.hasContent = !rnoContent.test( s.type );

		// Save the URL in case we're toying with the If-Modified-Since
		// and/or If-None-Match header later on
		// Remove hash to simplify url manipulation
		cacheURL = s.url.replace( rhash, "" );

		// More options handling for requests with no content
		if ( !s.hasContent ) {

			// Remember the hash so we can put it back
			uncached = s.url.slice( cacheURL.length );

			// If data is available and should be processed, append data to url
			if ( s.data && ( s.processData || typeof s.data === "string" ) ) {
				cacheURL += ( rquery.test( cacheURL ) ? "&" : "?" ) + s.data;

				// #9682: remove data so that it's not used in an eventual retry
				delete s.data;
			}

			// Add or update anti-cache param if needed
			if ( s.cache === false ) {
				cacheURL = cacheURL.replace( rantiCache, "$1" );
				uncached = ( rquery.test( cacheURL ) ? "&" : "?" ) + "_=" + ( nonce.guid++ ) +
					uncached;
			}

			// Put hash and anti-cache on the URL that will be requested (gh-1732)
			s.url = cacheURL + uncached;

		// Change '%20' to '+' if this is encoded form body content (gh-2658)
		} else if ( s.data && s.processData &&
			( s.contentType || "" ).indexOf( "application/x-www-form-urlencoded" ) === 0 ) {
			s.data = s.data.replace( r20, "+" );
		}

		// Set the If-Modified-Since and/or If-None-Match header, if in ifModified mode.
		if ( s.ifModified ) {
			if ( jQuery.lastModified[ cacheURL ] ) {
				jqXHR.setRequestHeader( "If-Modified-Since", jQuery.lastModified[ cacheURL ] );
			}
			if ( jQuery.etag[ cacheURL ] ) {
				jqXHR.setRequestHeader( "If-None-Match", jQuery.etag[ cacheURL ] );
			}
		}

		// Set the correct header, if data is being sent
		if ( s.data && s.hasContent && s.contentType !== false || options.contentType ) {
			jqXHR.setRequestHeader( "Content-Type", s.contentType );
		}

		// Set the Accepts header for the server, depending on the dataType
		jqXHR.setRequestHeader(
			"Accept",
			s.dataTypes[ 0 ] && s.accepts[ s.dataTypes[ 0 ] ] ?
				s.accepts[ s.dataTypes[ 0 ] ] +
					( s.dataTypes[ 0 ] !== "*" ? ", " + allTypes + "; q=0.01" : "" ) :
				s.accepts[ "*" ]
		);

		// Check for headers option
		for ( i in s.headers ) {
			jqXHR.setRequestHeader( i, s.headers[ i ] );
		}

		// Allow custom headers/mimetypes and early abort
		if ( s.beforeSend &&
			( s.beforeSend.call( callbackContext, jqXHR, s ) === false || completed ) ) {

			// Abort if not done already and return
			return jqXHR.abort();
		}

		// Aborting is no longer a cancellation
		strAbort = "abort";

		// Install callbacks on deferreds
		completeDeferred.add( s.complete );
		jqXHR.done( s.success );
		jqXHR.fail( s.error );

		// Get transport
		transport = inspectPrefiltersOrTransports( transports, s, options, jqXHR );

		// If no transport, we auto-abort
		if ( !transport ) {
			done( -1, "No Transport" );
		} else {
			jqXHR.readyState = 1;

			// Send global event
			if ( fireGlobals ) {
				globalEventContext.trigger( "ajaxSend", [ jqXHR, s ] );
			}

			// If request was aborted inside ajaxSend, stop there
			if ( completed ) {
				return jqXHR;
			}

			// Timeout
			if ( s.async && s.timeout > 0 ) {
				timeoutTimer = window.setTimeout( function() {
					jqXHR.abort( "timeout" );
				}, s.timeout );
			}

			try {
				completed = false;
				transport.send( requestHeaders, done );
			} catch ( e ) {

				// Rethrow post-completion exceptions
				if ( completed ) {
					throw e;
				}

				// Propagate others as results
				done( -1, e );
			}
		}

		// Callback for when everything is done
		function done( status, nativeStatusText, responses, headers ) {
			var isSuccess, success, error, response, modified,
				statusText = nativeStatusText;

			// Ignore repeat invocations
			if ( completed ) {
				return;
			}

			completed = true;

			// Clear timeout if it exists
			if ( timeoutTimer ) {
				window.clearTimeout( timeoutTimer );
			}

			// Dereference transport for early garbage collection
			// (no matter how long the jqXHR object will be used)
			transport = undefined;

			// Cache response headers
			responseHeadersString = headers || "";

			// Set readyState
			jqXHR.readyState = status > 0 ? 4 : 0;

			// Determine if successful
			isSuccess = status >= 200 && status < 300 || status === 304;

			// Get response data
			if ( responses ) {
				response = ajaxHandleResponses( s, jqXHR, responses );
			}

			// Use a noop converter for missing script
			if ( !isSuccess && jQuery.inArray( "script", s.dataTypes ) > -1 ) {
				s.converters[ "text script" ] = function() {};
			}

			// Convert no matter what (that way responseXXX fields are always set)
			response = ajaxConvert( s, response, jqXHR, isSuccess );

			// If successful, handle type chaining
			if ( isSuccess ) {

				// Set the If-Modified-Since and/or If-None-Match header, if in ifModified mode.
				if ( s.ifModified ) {
					modified = jqXHR.getResponseHeader( "Last-Modified" );
					if ( modified ) {
						jQuery.lastModified[ cacheURL ] = modified;
					}
					modified = jqXHR.getResponseHeader( "etag" );
					if ( modified ) {
						jQuery.etag[ cacheURL ] = modified;
					}
				}

				// if no content
				if ( status === 204 || s.type === "HEAD" ) {
					statusText = "nocontent";

				// if not modified
				} else if ( status === 304 ) {
					statusText = "notmodified";

				// If we have data, let's convert it
				} else {
					statusText = response.state;
					success = response.data;
					error = response.error;
					isSuccess = !error;
				}
			} else {

				// Extract error from statusText and normalize for non-aborts
				error = statusText;
				if ( status || !statusText ) {
					statusText = "error";
					if ( status < 0 ) {
						status = 0;
					}
				}
			}

			// Set data for the fake xhr object
			jqXHR.status = status;
			jqXHR.statusText = ( nativeStatusText || statusText ) + "";

			// Success/Error
			if ( isSuccess ) {
				deferred.resolveWith( callbackContext, [ success, statusText, jqXHR ] );
			} else {
				deferred.rejectWith( callbackContext, [ jqXHR, statusText, error ] );
			}

			// Status-dependent callbacks
			jqXHR.statusCode( statusCode );
			statusCode = undefined;

			if ( fireGlobals ) {
				globalEventContext.trigger( isSuccess ? "ajaxSuccess" : "ajaxError",
					[ jqXHR, s, isSuccess ? success : error ] );
			}

			// Complete
			completeDeferred.fireWith( callbackContext, [ jqXHR, statusText ] );

			if ( fireGlobals ) {
				globalEventContext.trigger( "ajaxComplete", [ jqXHR, s ] );

				// Handle the global AJAX counter
				if ( !( --jQuery.active ) ) {
					jQuery.event.trigger( "ajaxStop" );
				}
			}
		}

		return jqXHR;
	},

	getJSON: function( url, data, callback ) {
		return jQuery.get( url, data, callback, "json" );
	},

	getScript: function( url, callback ) {
		return jQuery.get( url, undefined, callback, "script" );
	}
} );

jQuery.each( [ "get", "post" ], function( _i, method ) {
	jQuery[ method ] = function( url, data, callback, type ) {

		// Shift arguments if data argument was omitted
		if ( isFunction( data ) ) {
			type = type || callback;
			callback = data;
			data = undefined;
		}

		// The url can be an options object (which then must have .url)
		return jQuery.ajax( jQuery.extend( {
			url: url,
			type: method,
			dataType: type,
			data: data,
			success: callback
		}, jQuery.isPlainObject( url ) && url ) );
	};
} );

jQuery.ajaxPrefilter( function( s ) {
	var i;
	for ( i in s.headers ) {
		if ( i.toLowerCase() === "content-type" ) {
			s.contentType = s.headers[ i ] || "";
		}
	}
} );


jQuery._evalUrl = function( url, options, doc ) {
	return jQuery.ajax( {
		url: url,

		// Make this explicit, since user can override this through ajaxSetup (#11264)
		type: "GET",
		dataType: "script",
		cache: true,
		async: false,
		global: false,

		// Only evaluate the response if it is successful (gh-4126)
		// dataFilter is not invoked for failure responses, so using it instead
		// of the default converter is kludgy but it works.
		converters: {
			"text script": function() {}
		},
		dataFilter: function( response ) {
			jQuery.globalEval( response, options, doc );
		}
	} );
};


jQuery.fn.extend( {
	wrapAll: function( html ) {
		var wrap;

		if ( this[ 0 ] ) {
			if ( isFunction( html ) ) {
				html = html.call( this[ 0 ] );
			}

			// The elements to wrap the target around
			wrap = jQuery( html, this[ 0 ].ownerDocument ).eq( 0 ).clone( true );

			if ( this[ 0 ].parentNode ) {
				wrap.insertBefore( this[ 0 ] );
			}

			wrap.map( function() {
				var elem = this;

				while ( elem.firstElementChild ) {
					elem = elem.firstElementChild;
				}

				return elem;
			} ).append( this );
		}

		return this;
	},

	wrapInner: function( html ) {
		if ( isFunction( html ) ) {
			return this.each( function( i ) {
				jQuery( this ).wrapInner( html.call( this, i ) );
			} );
		}

		return this.each( function() {
			var self = jQuery( this ),
				contents = self.contents();

			if ( contents.length ) {
				contents.wrapAll( html );

			} else {
				self.append( html );
			}
		} );
	},

	wrap: function( html ) {
		var htmlIsFunction = isFunction( html );

		return this.each( function( i ) {
			jQuery( this ).wrapAll( htmlIsFunction ? html.call( this, i ) : html );
		} );
	},

	unwrap: function( selector ) {
		this.parent( selector ).not( "body" ).each( function() {
			jQuery( this ).replaceWith( this.childNodes );
		} );
		return this;
	}
} );


jQuery.expr.pseudos.hidden = function( elem ) {
	return !jQuery.expr.pseudos.visible( elem );
};
jQuery.expr.pseudos.visible = function( elem ) {
	return !!( elem.offsetWidth || elem.offsetHeight || elem.getClientRects().length );
};




jQuery.ajaxSettings.xhr = function() {
	try {
		return new window.XMLHttpRequest();
	} catch ( e ) {}
};

var xhrSuccessStatus = {

		// File protocol always yields status code 0, assume 200
		0: 200,

		// Support: IE <=9 only
		// #1450: sometimes IE returns 1223 when it should be 204
		1223: 204
	},
	xhrSupported = jQuery.ajaxSettings.xhr();

support.cors = !!xhrSupported && ( "withCredentials" in xhrSupported );
support.ajax = xhrSupported = !!xhrSupported;

jQuery.ajaxTransport( function( options ) {
	var callback, errorCallback;

	// Cross domain only allowed if supported through XMLHttpRequest
	if ( support.cors || xhrSupported && !options.crossDomain ) {
		return {
			send: function( headers, complete ) {
				var i,
					xhr = options.xhr();

				xhr.open(
					options.type,
					options.url,
					options.async,
					options.username,
					options.password
				);

				// Apply custom fields if provided
				if ( options.xhrFields ) {
					for ( i in options.xhrFields ) {
						xhr[ i ] = options.xhrFields[ i ];
					}
				}

				// Override mime type if needed
				if ( options.mimeType && xhr.overrideMimeType ) {
					xhr.overrideMimeType( options.mimeType );
				}

				// X-Requested-With header
				// For cross-domain requests, seeing as conditions for a preflight are
				// akin to a jigsaw puzzle, we simply never set it to be sure.
				// (it can always be set on a per-request basis or even using ajaxSetup)
				// For same-domain requests, won't change header if already provided.
				if ( !options.crossDomain && !headers[ "X-Requested-With" ] ) {
					headers[ "X-Requested-With" ] = "XMLHttpRequest";
				}

				// Set headers
				for ( i in headers ) {
					xhr.setRequestHeader( i, headers[ i ] );
				}

				// Callback
				callback = function( type ) {
					return function() {
						if ( callback ) {
							callback = errorCallback = xhr.onload =
								xhr.onerror = xhr.onabort = xhr.ontimeout =
									xhr.onreadystatechange = null;

							if ( type === "abort" ) {
								xhr.abort();
							} else if ( type === "error" ) {

								// Support: IE <=9 only
								// On a manual native abort, IE9 throws
								// errors on any property access that is not readyState
								if ( typeof xhr.status !== "number" ) {
									complete( 0, "error" );
								} else {
									complete(

										// File: protocol always yields status 0; see #8605, #14207
										xhr.status,
										xhr.statusText
									);
								}
							} else {
								complete(
									xhrSuccessStatus[ xhr.status ] || xhr.status,
									xhr.statusText,

									// Support: IE <=9 only
									// IE9 has no XHR2 but throws on binary (trac-11426)
									// For XHR2 non-text, let the caller handle it (gh-2498)
									( xhr.responseType || "text" ) !== "text"  ||
									typeof xhr.responseText !== "string" ?
										{ binary: xhr.response } :
										{ text: xhr.responseText },
									xhr.getAllResponseHeaders()
								);
							}
						}
					};
				};

				// Listen to events
				xhr.onload = callback();
				errorCallback = xhr.onerror = xhr.ontimeout = callback( "error" );

				// Support: IE 9 only
				// Use onreadystatechange to replace onabort
				// to handle uncaught aborts
				if ( xhr.onabort !== undefined ) {
					xhr.onabort = errorCallback;
				} else {
					xhr.onreadystatechange = function() {

						// Check readyState before timeout as it changes
						if ( xhr.readyState === 4 ) {

							// Allow onerror to be called first,
							// but that will not handle a native abort
							// Also, save errorCallback to a variable
							// as xhr.onerror cannot be accessed
							window.setTimeout( function() {
								if ( callback ) {
									errorCallback();
								}
							} );
						}
					};
				}

				// Create the abort callback
				callback = callback( "abort" );

				try {

					// Do send the request (this may raise an exception)
					xhr.send( options.hasContent && options.data || null );
				} catch ( e ) {

					// #14683: Only rethrow if this hasn't been notified as an error yet
					if ( callback ) {
						throw e;
					}
				}
			},

			abort: function() {
				if ( callback ) {
					callback();
				}
			}
		};
	}
} );




// Prevent auto-execution of scripts when no explicit dataType was provided (See gh-2432)
jQuery.ajaxPrefilter( function( s ) {
	if ( s.crossDomain ) {
		s.contents.script = false;
	}
} );

// Install script dataType
jQuery.ajaxSetup( {
	accepts: {
		script: "text/javascript, application/javascript, " +
			"application/ecmascript, application/x-ecmascript"
	},
	contents: {
		script: /\b(?:java|ecma)script\b/
	},
	converters: {
		"text script": function( text ) {
			jQuery.globalEval( text );
			return text;
		}
	}
} );

// Handle cache's special case and crossDomain
jQuery.ajaxPrefilter( "script", function( s ) {
	if ( s.cache === undefined ) {
		s.cache = false;
	}
	if ( s.crossDomain ) {
		s.type = "GET";
	}
} );

// Bind script tag hack transport
jQuery.ajaxTransport( "script", function( s ) {

	// This transport only deals with cross domain or forced-by-attrs requests
	if ( s.crossDomain || s.scriptAttrs ) {
		var script, callback;
		return {
			send: function( _, complete ) {
				script = jQuery( "<script>" )
					.attr( s.scriptAttrs || {} )
					.prop( { charset: s.scriptCharset, src: s.url } )
					.on( "load error", callback = function( evt ) {
						script.remove();
						callback = null;
						if ( evt ) {
							complete( evt.type === "error" ? 404 : 200, evt.type );
						}
					} );

				// Use native DOM manipulation to avoid our domManip AJAX trickery
				document.head.appendChild( script[ 0 ] );
			},
			abort: function() {
				if ( callback ) {
					callback();
				}
			}
		};
	}
} );




var oldCallbacks = [],
	rjsonp = /(=)\?(?=&|$)|\?\?/;

// Default jsonp settings
jQuery.ajaxSetup( {
	jsonp: "callback",
	jsonpCallback: function() {
		var callback = oldCallbacks.pop() || ( jQuery.expando + "_" + ( nonce.guid++ ) );
		this[ callback ] = true;
		return callback;
	}
} );

// Detect, normalize options and install callbacks for jsonp requests
jQuery.ajaxPrefilter( "json jsonp", function( s, originalSettings, jqXHR ) {

	var callbackName, overwritten, responseContainer,
		jsonProp = s.jsonp !== false && ( rjsonp.test( s.url ) ?
			"url" :
			typeof s.data === "string" &&
				( s.contentType || "" )
					.indexOf( "application/x-www-form-urlencoded" ) === 0 &&
				rjsonp.test( s.data ) && "data"
		);

	// Handle iff the expected data type is "jsonp" or we have a parameter to set
	if ( jsonProp || s.dataTypes[ 0 ] === "jsonp" ) {

		// Get callback name, remembering preexisting value associated with it
		callbackName = s.jsonpCallback = isFunction( s.jsonpCallback ) ?
			s.jsonpCallback() :
			s.jsonpCallback;

		// Insert callback into url or form data
		if ( jsonProp ) {
			s[ jsonProp ] = s[ jsonProp ].replace( rjsonp, "$1" + callbackName );
		} else if ( s.jsonp !== false ) {
			s.url += ( rquery.test( s.url ) ? "&" : "?" ) + s.jsonp + "=" + callbackName;
		}

		// Use data converter to retrieve json after script execution
		s.converters[ "script json" ] = function() {
			if ( !responseContainer ) {
				jQuery.error( callbackName + " was not called" );
			}
			return responseContainer[ 0 ];
		};

		// Force json dataType
		s.dataTypes[ 0 ] = "json";

		// Install callback
		overwritten = window[ callbackName ];
		window[ callbackName ] = function() {
			responseContainer = arguments;
		};

		// Clean-up function (fires after converters)
		jqXHR.always( function() {

			// If previous value didn't exist - remove it
			if ( overwritten === undefined ) {
				jQuery( window ).removeProp( callbackName );

			// Otherwise restore preexisting value
			} else {
				window[ callbackName ] = overwritten;
			}

			// Save back as free
			if ( s[ callbackName ] ) {

				// Make sure that re-using the options doesn't screw things around
				s.jsonpCallback = originalSettings.jsonpCallback;

				// Save the callback name for future use
				oldCallbacks.push( callbackName );
			}

			// Call if it was a function and we have a response
			if ( responseContainer && isFunction( overwritten ) ) {
				overwritten( responseContainer[ 0 ] );
			}

			responseContainer = overwritten = undefined;
		} );

		// Delegate to script
		return "script";
	}
} );




// Support: Safari 8 only
// In Safari 8 documents created via document.implementation.createHTMLDocument
// collapse sibling forms: the second one becomes a child of the first one.
// Because of that, this security measure has to be disabled in Safari 8.
// https://bugs.webkit.org/show_bug.cgi?id=137337
support.createHTMLDocument = ( function() {
	var body = document.implementation.createHTMLDocument( "" ).body;
	body.innerHTML = "<form></form><form></form>";
	return body.childNodes.length === 2;
} )();


// Argument "data" should be string of html
// context (optional): If specified, the fragment will be created in this context,
// defaults to document
// keepScripts (optional): If true, will include scripts passed in the html string
jQuery.parseHTML = function( data, context, keepScripts ) {
	if ( typeof data !== "string" ) {
		return [];
	}
	if ( typeof context === "boolean" ) {
		keepScripts = context;
		context = false;
	}

	var base, parsed, scripts;

	if ( !context ) {

		// Stop scripts or inline event handlers from being executed immediately
		// by using document.implementation
		if ( support.createHTMLDocument ) {
			context = document.implementation.createHTMLDocument( "" );

			// Set the base href for the created document
			// so any parsed elements with URLs
			// are based on the document's URL (gh-2965)
			base = context.createElement( "base" );
			base.href = document.location.href;
			context.head.appendChild( base );
		} else {
			context = document;
		}
	}

	parsed = rsingleTag.exec( data );
	scripts = !keepScripts && [];

	// Single tag
	if ( parsed ) {
		return [ context.createElement( parsed[ 1 ] ) ];
	}

	parsed = buildFragment( [ data ], context, scripts );

	if ( scripts && scripts.length ) {
		jQuery( scripts ).remove();
	}

	return jQuery.merge( [], parsed.childNodes );
};


/**
 * Load a url into a page
 */
jQuery.fn.load = function( url, params, callback ) {
	var selector, type, response,
		self = this,
		off = url.indexOf( " " );

	if ( off > -1 ) {
		selector = stripAndCollapse( url.slice( off ) );
		url = url.slice( 0, off );
	}

	// If it's a function
	if ( isFunction( params ) ) {

		// We assume that it's the callback
		callback = params;
		params = undefined;

	// Otherwise, build a param string
	} else if ( params && typeof params === "object" ) {
		type = "POST";
	}

	// If we have elements to modify, make the request
	if ( self.length > 0 ) {
		jQuery.ajax( {
			url: url,

			// If "type" variable is undefined, then "GET" method will be used.
			// Make value of this field explicit since
			// user can override it through ajaxSetup method
			type: type || "GET",
			dataType: "html",
			data: params
		} ).done( function( responseText ) {

			// Save response for use in complete callback
			response = arguments;

			self.html( selector ?

				// If a selector was specified, locate the right elements in a dummy div
				// Exclude scripts to avoid IE 'Permission Denied' errors
				jQuery( "<div>" ).append( jQuery.parseHTML( responseText ) ).find( selector ) :

				// Otherwise use the full result
				responseText );

		// If the request succeeds, this function gets "data", "status", "jqXHR"
		// but they are ignored because response was set above.
		// If it fails, this function gets "jqXHR", "status", "error"
		} ).always( callback && function( jqXHR, status ) {
			self.each( function() {
				callback.apply( this, response || [ jqXHR.responseText, status, jqXHR ] );
			} );
		} );
	}

	return this;
};




jQuery.expr.pseudos.animated = function( elem ) {
	return jQuery.grep( jQuery.timers, function( fn ) {
		return elem === fn.elem;
	} ).length;
};




jQuery.offset = {
	setOffset: function( elem, options, i ) {
		var curPosition, curLeft, curCSSTop, curTop, curOffset, curCSSLeft, calculatePosition,
			position = jQuery.css( elem, "position" ),
			curElem = jQuery( elem ),
			props = {};

		// Set position first, in-case top/left are set even on static elem
		if ( position === "static" ) {
			elem.style.position = "relative";
		}

		curOffset = curElem.offset();
		curCSSTop = jQuery.css( elem, "top" );
		curCSSLeft = jQuery.css( elem, "left" );
		calculatePosition = ( position === "absolute" || position === "fixed" ) &&
			( curCSSTop + curCSSLeft ).indexOf( "auto" ) > -1;

		// Need to be able to calculate position if either
		// top or left is auto and position is either absolute or fixed
		if ( calculatePosition ) {
			curPosition = curElem.position();
			curTop = curPosition.top;
			curLeft = curPosition.left;

		} else {
			curTop = parseFloat( curCSSTop ) || 0;
			curLeft = parseFloat( curCSSLeft ) || 0;
		}

		if ( isFunction( options ) ) {

			// Use jQuery.extend here to allow modification of coordinates argument (gh-1848)
			options = options.call( elem, i, jQuery.extend( {}, curOffset ) );
		}

		if ( options.top != null ) {
			props.top = ( options.top - curOffset.top ) + curTop;
		}
		if ( options.left != null ) {
			props.left = ( options.left - curOffset.left ) + curLeft;
		}

		if ( "using" in options ) {
			options.using.call( elem, props );

		} else {
			if ( typeof props.top === "number" ) {
				props.top += "px";
			}
			if ( typeof props.left === "number" ) {
				props.left += "px";
			}
			curElem.css( props );
		}
	}
};

jQuery.fn.extend( {

	// offset() relates an element's border box to the document origin
	offset: function( options ) {

		// Preserve chaining for setter
		if ( arguments.length ) {
			return options === undefined ?
				this :
				this.each( function( i ) {
					jQuery.offset.setOffset( this, options, i );
				} );
		}

		var rect, win,
			elem = this[ 0 ];

		if ( !elem ) {
			return;
		}

		// Return zeros for disconnected and hidden (display: none) elements (gh-2310)
		// Support: IE <=11 only
		// Running getBoundingClientRect on a
		// disconnected node in IE throws an error
		if ( !elem.getClientRects().length ) {
			return { top: 0, left: 0 };
		}

		// Get document-relative position by adding viewport scroll to viewport-relative gBCR
		rect = elem.getBoundingClientRect();
		win = elem.ownerDocument.defaultView;
		return {
			top: rect.top + win.pageYOffset,
			left: rect.left + win.pageXOffset
		};
	},

	// position() relates an element's margin box to its offset parent's padding box
	// This corresponds to the behavior of CSS absolute positioning
	position: function() {
		if ( !this[ 0 ] ) {
			return;
		}

		var offsetParent, offset, doc,
			elem = this[ 0 ],
			parentOffset = { top: 0, left: 0 };

		// position:fixed elements are offset from the viewport, which itself always has zero offset
		if ( jQuery.css( elem, "position" ) === "fixed" ) {

			// Assume position:fixed implies availability of getBoundingClientRect
			offset = elem.getBoundingClientRect();

		} else {
			offset = this.offset();

			// Account for the *real* offset parent, which can be the document or its root element
			// when a statically positioned element is identified
			doc = elem.ownerDocument;
			offsetParent = elem.offsetParent || doc.documentElement;
			while ( offsetParent &&
				( offsetParent === doc.body || offsetParent === doc.documentElement ) &&
				jQuery.css( offsetParent, "position" ) === "static" ) {

				offsetParent = offsetParent.parentNode;
			}
			if ( offsetParent && offsetParent !== elem && offsetParent.nodeType === 1 ) {

				// Incorporate borders into its offset, since they are outside its content origin
				parentOffset = jQuery( offsetParent ).offset();
				parentOffset.top += jQuery.css( offsetParent, "borderTopWidth", true );
				parentOffset.left += jQuery.css( offsetParent, "borderLeftWidth", true );
			}
		}

		// Subtract parent offsets and element margins
		return {
			top: offset.top - parentOffset.top - jQuery.css( elem, "marginTop", true ),
			left: offset.left - parentOffset.left - jQuery.css( elem, "marginLeft", true )
		};
	},

	// This method will return documentElement in the following cases:
	// 1) For the element inside the iframe without offsetParent, this method will return
	//    documentElement of the parent window
	// 2) For the hidden or detached element
	// 3) For body or html element, i.e. in case of the html node - it will return itself
	//
	// but those exceptions were never presented as a real life use-cases
	// and might be considered as more preferable results.
	//
	// This logic, however, is not guaranteed and can change at any point in the future
	offsetParent: function() {
		return this.map( function() {
			var offsetParent = this.offsetParent;

			while ( offsetParent && jQuery.css( offsetParent, "position" ) === "static" ) {
				offsetParent = offsetParent.offsetParent;
			}

			return offsetParent || documentElement;
		} );
	}
} );

// Create scrollLeft and scrollTop methods
jQuery.each( { scrollLeft: "pageXOffset", scrollTop: "pageYOffset" }, function( method, prop ) {
	var top = "pageYOffset" === prop;

	jQuery.fn[ method ] = function( val ) {
		return access( this, function( elem, method, val ) {

			// Coalesce documents and windows
			var win;
			if ( isWindow( elem ) ) {
				win = elem;
			} else if ( elem.nodeType === 9 ) {
				win = elem.defaultView;
			}

			if ( val === undefined ) {
				return win ? win[ prop ] : elem[ method ];
			}

			if ( win ) {
				win.scrollTo(
					!top ? val : win.pageXOffset,
					top ? val : win.pageYOffset
				);

			} else {
				elem[ method ] = val;
			}
		}, method, val, arguments.length );
	};
} );

// Support: Safari <=7 - 9.1, Chrome <=37 - 49
// Add the top/left cssHooks using jQuery.fn.position
// Webkit bug: https://bugs.webkit.org/show_bug.cgi?id=29084
// Blink bug: https://bugs.chromium.org/p/chromium/issues/detail?id=589347
// getComputedStyle returns percent when specified for top/left/bottom/right;
// rather than make the css module depend on the offset module, just check for it here
jQuery.each( [ "top", "left" ], function( _i, prop ) {
	jQuery.cssHooks[ prop ] = addGetHookIf( support.pixelPosition,
		function( elem, computed ) {
			if ( computed ) {
				computed = curCSS( elem, prop );

				// If curCSS returns percentage, fallback to offset
				return rnumnonpx.test( computed ) ?
					jQuery( elem ).position()[ prop ] + "px" :
					computed;
			}
		}
	);
} );


// Create innerHeight, innerWidth, height, width, outerHeight and outerWidth methods
jQuery.each( { Height: "height", Width: "width" }, function( name, type ) {
	jQuery.each( { padding: "inner" + name, content: type, "": "outer" + name },
		function( defaultExtra, funcName ) {

		// Margin is only for outerHeight, outerWidth
		jQuery.fn[ funcName ] = function( margin, value ) {
			var chainable = arguments.length && ( defaultExtra || typeof margin !== "boolean" ),
				extra = defaultExtra || ( margin === true || value === true ? "margin" : "border" );

			return access( this, function( elem, type, value ) {
				var doc;

				if ( isWindow( elem ) ) {

					// $( window ).outerWidth/Height return w/h including scrollbars (gh-1729)
					return funcName.indexOf( "outer" ) === 0 ?
						elem[ "inner" + name ] :
						elem.document.documentElement[ "client" + name ];
				}

				// Get document width or height
				if ( elem.nodeType === 9 ) {
					doc = elem.documentElement;

					// Either scroll[Width/Height] or offset[Width/Height] or client[Width/Height],
					// whichever is greatest
					return Math.max(
						elem.body[ "scroll" + name ], doc[ "scroll" + name ],
						elem.body[ "offset" + name ], doc[ "offset" + name ],
						doc[ "client" + name ]
					);
				}

				return value === undefined ?

					// Get width or height on the element, requesting but not forcing parseFloat
					jQuery.css( elem, type, extra ) :

					// Set width or height on the element
					jQuery.style( elem, type, value, extra );
			}, type, chainable ? margin : undefined, chainable );
		};
	} );
} );


jQuery.each( [
	"ajaxStart",
	"ajaxStop",
	"ajaxComplete",
	"ajaxError",
	"ajaxSuccess",
	"ajaxSend"
], function( _i, type ) {
	jQuery.fn[ type ] = function( fn ) {
		return this.on( type, fn );
	};
} );




jQuery.fn.extend( {

	bind: function( types, data, fn ) {
		return this.on( types, null, data, fn );
	},
	unbind: function( types, fn ) {
		return this.off( types, null, fn );
	},

	delegate: function( selector, types, data, fn ) {
		return this.on( types, selector, data, fn );
	},
	undelegate: function( selector, types, fn ) {

		// ( namespace ) or ( selector, types [, fn] )
		return arguments.length === 1 ?
			this.off( selector, "**" ) :
			this.off( types, selector || "**", fn );
	},

	hover: function( fnOver, fnOut ) {
		return this.mouseenter( fnOver ).mouseleave( fnOut || fnOver );
	}
} );

jQuery.each( ( "blur focus focusin focusout resize scroll click dblclick " +
	"mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave " +
	"change select submit keydown keypress keyup contextmenu" ).split( " " ),
	function( _i, name ) {

		// Handle event binding
		jQuery.fn[ name ] = function( data, fn ) {
			return arguments.length > 0 ?
				this.on( name, null, data, fn ) :
				this.trigger( name );
		};
	} );




// Support: Android <=4.0 only
// Make sure we trim BOM and NBSP
var rtrim = /^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g;

// Bind a function to a context, optionally partially applying any
// arguments.
// jQuery.proxy is deprecated to promote standards (specifically Function#bind)
// However, it is not slated for removal any time soon
jQuery.proxy = function( fn, context ) {
	var tmp, args, proxy;

	if ( typeof context === "string" ) {
		tmp = fn[ context ];
		context = fn;
		fn = tmp;
	}

	// Quick check to determine if target is callable, in the spec
	// this throws a TypeError, but we will just return undefined.
	if ( !isFunction( fn ) ) {
		return undefined;
	}

	// Simulated bind
	args = slice.call( arguments, 2 );
	proxy = function() {
		return fn.apply( context || this, args.concat( slice.call( arguments ) ) );
	};

	// Set the guid of unique handler to the same of original handler, so it can be removed
	proxy.guid = fn.guid = fn.guid || jQuery.guid++;

	return proxy;
};

jQuery.holdReady = function( hold ) {
	if ( hold ) {
		jQuery.readyWait++;
	} else {
		jQuery.ready( true );
	}
};
jQuery.isArray = Array.isArray;
jQuery.parseJSON = JSON.parse;
jQuery.nodeName = nodeName;
jQuery.isFunction = isFunction;
jQuery.isWindow = isWindow;
jQuery.camelCase = camelCase;
jQuery.type = toType;

jQuery.now = Date.now;

jQuery.isNumeric = function( obj ) {

	// As of jQuery 3.0, isNumeric is limited to
	// strings and numbers (primitives or objects)
	// that can be coerced to finite numbers (gh-2662)
	var type = jQuery.type( obj );
	return ( type === "number" || type === "string" ) &&

		// parseFloat NaNs numeric-cast false positives ("")
		// ...but misinterprets leading-number strings, particularly hex literals ("0x...")
		// subtraction forces infinities to NaN
		!isNaN( obj - parseFloat( obj ) );
};

jQuery.trim = function( text ) {
	return text == null ?
		"" :
		( text + "" ).replace( rtrim, "" );
};



// Register as a named AMD module, since jQuery can be concatenated with other
// files that may use define, but not via a proper concatenation script that
// understands anonymous AMD modules. A named AMD is safest and most robust
// way to register. Lowercase jquery is used because AMD module names are
// derived from file names, and jQuery is normally delivered in a lowercase
// file name. Do this after creating the global so that if an AMD module wants
// to call noConflict to hide this version of jQuery, it will work.

// Note that for maximum portability, libraries that are not jQuery should
// declare themselves as anonymous modules, and avoid setting a global if an
// AMD loader is present. jQuery is a special case. For more information, see
// https://github.com/jrburke/requirejs/wiki/Updating-existing-libraries#wiki-anon

if ( true ) {
	!(__WEBPACK_AMD_DEFINE_ARRAY__ = [], __WEBPACK_AMD_DEFINE_RESULT__ = (function() {
		return jQuery;
	}).apply(exports, __WEBPACK_AMD_DEFINE_ARRAY__),
				__WEBPACK_AMD_DEFINE_RESULT__ !== undefined && (module.exports = __WEBPACK_AMD_DEFINE_RESULT__));
}




var

	// Map over jQuery in case of overwrite
	_jQuery = window.jQuery,

	// Map over the $ in case of overwrite
	_$ = window.$;

jQuery.noConflict = function( deep ) {
	if ( window.$ === jQuery ) {
		window.$ = _$;
	}

	if ( deep && window.jQuery === jQuery ) {
		window.jQuery = _jQuery;
	}

	return jQuery;
};

// Expose jQuery and $ identifiers, even in AMD
// (#7102#comment:10, https://github.com/jquery/jquery/pull/557)
// and CommonJS for browser emulators (#13566)
if ( typeof noGlobal === "undefined" ) {
	window.jQuery = window.$ = jQuery;
}




return jQuery;
} );


/***/ }),
/* 1 */
/***/ (function(module, exports) {

var g;

// This works in non-strict mode
g = (function() {
	return this;
})();

try {
	// This works if eval is allowed (see CSP)
	g = g || new Function("return this")();
} catch (e) {
	// This works if the window reference is available
	if (typeof window === "object") g = window;
}

// g can still be undefined, but nothing to do about it...
// We return undefined, instead of nothing here, so it's
// easier to handle this case. if(!global) { ...}

module.exports = g;


/***/ }),
/* 2 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var jquery__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(0);
/* harmony import */ var jquery__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(jquery__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var metro4_build_css_metro_all_css__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3);
/* harmony import */ var metro4_build_css_metro_all_css__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(metro4_build_css_metro_all_css__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var metro4_build_js_metro_min_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(4);
/* harmony import */ var metro4_build_js_metro_min_js__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(metro4_build_js_metro_min_js__WEBPACK_IMPORTED_MODULE_2__);

//import 'bootstrap/dist/css/bootstrap.min.css';

//import 'metro4/build/css/metro-icons.css';



jquery__WEBPACK_IMPORTED_MODULE_0___default()("#buttonRemove").on("click", function(e) {
	var table = Metro.getPlugin("#tableEvents", "table");
	var rowsSelected=table.getSelectedItems();
	for(var i=0;i<rowsSelected.length;i++) {
		var _id=rowsSelected[i][3];
		var url="./deleteTask";
		jquery__WEBPACK_IMPORTED_MODULE_0___default.a.get(url,{id:String(_id)})
		.done(function(response){
			location.reload();
			//console.log(response);
		})
		.fail(function(err){
			console.log(err);
		});
	}
});


function _EventsTable() {
	
}

/* harmony default export */ __webpack_exports__["default"] = (_EventsTable);

/***/ }),
/* 3 */
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ }),
/* 4 */
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(setImmediate) {var __WEBPACK_AMD_DEFINE_FACTORY__, __WEBPACK_AMD_DEFINE_RESULT__;/*
 * Metro 4 Components Library v4.3.10  (https://metroui.org.ua)
 * Copyright 2012-2020 Sergey Pimenov
 * Built at 12/07/2020 20:25:57
 * Licensed under MIT
 */

!function(e,y){"use strict";var i=["opacity","zIndex"];function o(e){return!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length)}function I(e){return e===y||null===e}function g(e){return e.replace(/-([a-z])/g,function(e,t){return t.toUpperCase()})}function w(e){var t;return!(!e||"[object Object]"!==Object.prototype.toString.call(e))&&(!(t=e.prototype!==y)||t.constructor&&"function"==typeof t.constructor)}function C(e){for(var t in e)if(c(e,t))return!1;return!0}function a(e){return e instanceof Object&&"length"in e}function s(e,t){return t=t||" ",e.split(t).map(function(e){return(""+e).trim()}).filter(function(e){return""!==e})}function m(e,t){return t||(t=[0,""]),e=String(e),t[0]=parseFloat(e),t[1]=e.match(/[\d.\-+]*\s*(.*)/)[1]||"",t}function v(e,t){var n=/[+-]?\d*\.?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(%|px|pt|em|rem|in|cm|mm|ex|ch|pc|vw|vh|vmin|vmax|deg|rad|turn)?$/.exec(e);return void 0!==n[1]?n[1]:t}function r(e,t,n){t=g(t),-1<["scrollLeft","scrollTop"].indexOf(t)?e[t]=parseInt(n):e.style[t]=isNaN(n)||-1<i.indexOf(""+t)?n:n+"px"}function n(e){return 1===e.nodeType||9===e.nodeType||!+e.nodeType}function l(e,t,n){var i;return I(n)&&1===e.nodeType&&(i="data-"+t.replace(/[A-Z]/g,"-$&").toLowerCase(),"string"==typeof(n=e.getAttribute(i))?(n=function(t){try{return JSON.parse(t)}catch(e){return t}}(n),b.set(e,t,n)):n=y),n}function u(e){return"string"!=typeof e?y:e.replace(/-/g,"").toLowerCase()}function c(e,t){return Object.prototype.hasOwnProperty.call(e,t)}!function(t){if(!t.setImmediate){var i,n,s,a=1,o={},r=!1,e=Object.getPrototypeOf&&Object.getPrototypeOf(t);e=e&&e.setTimeout?e:t,i="[object process]"==={}.toString.call(t.process)?function(e){t.process.nextTick(function(){c(e)})}:t.MessageChannel?((s=new MessageChannel).port1.onmessage=function(e){c(e.data)},function(e){s.port2.postMessage(e)}):(n="setImmediate$"+Math.random()+"$",t.addEventListener("message",function(e){e.source===t&&"string"==typeof e.data&&0===e.data.indexOf(n)&&c(+e.data.slice(n.length))},!1),function(e){t.postMessage(n+e,"*")}),e.setImmediate=function(e){"function"!=typeof e&&(e=new Function(""+e));for(var t=new Array(arguments.length-1),n=0;n<t.length;n++)t[n]=arguments[n+1];return o[a]={callback:e,args:t},i(a),a++},e.clearImmediate=l}function l(e){delete o[e]}function c(e){if(r)setTimeout(c,0,e);else{var t=o[e];if(t){r=!0;try{!function(e){var t=e.callback,n=e.args;switch(n.length){case 0:t();break;case 1:t(n[0]);break;case 2:t(n[0],n[1]);break;case 3:t(n[0],n[1],n[2]);break;default:t.apply(y,n)}}(t)}finally{l(e),r=!1}}}}}("undefined"==typeof self?void 0===e?window:e:self),function(e){if(!e.Promise){var n,i="pending",s="sealed",o="fulfilled",r="rejected",a=function(){},l="undefined"!=typeof setImmediate?setImmediate:setTimeout,c=[];b.prototype={constructor:b,state_:i,then_:null,data_:y,then:function(e,t){var n={owner:this,then:new this.constructor(a),fulfilled:e,rejected:t};return this.state_===o||this.state_===r?u(h,n):this.then_.push(n),n.then},done:function(e){return this.then(e,null)},always:function(e){return this.then(e,e)},catch:function(e){return this.then(null,e)}},b.all=function(r){if(!t(r))throw new TypeError("You must pass an array to Promise.all().");return new this(function(n,e){var i=[],s=0;function t(t){return s++,function(e){i[t]=e,--s||n(i)}}for(var a,o=0;o<r.length;o++)(a=r[o])&&"function"==typeof a.then?a.then(t(o),e):i[o]=a;s||n(i)})},b.race=function(s){if(!t(s))throw new TypeError("You must pass an array to Promise.race().");return new this(function(e,t){for(var n,i=0;i<s.length;i++)(n=s[i])&&"function"==typeof n.then?n.then(e,t):e(n)})},b.resolve=function(t){return t&&"object"==typeof t&&t.constructor===this?t:new this(function(e){e(t)})},b.reject=function(n){return new this(function(e,t){t(n)})},void 0===e.Promise&&(e.Promise=b)}function t(e){return"[object Array]"===Object.prototype.toString.call(e)}function d(){for(var e=0;e<c.length;e++)c[e][0](c[e][1]);n=!(c=[])}function u(e,t){c.push([e,t]),n||(n=!0,l(d,0))}function h(e){var t=e.owner,n=t.state_,i=t.data_,s=e[n],a=e.then;if("function"==typeof s){n=o;try{i=s(i)}catch(e){v(a,e)}}p(a,i)||(n===o&&f(a,i),n===r&&v(a,i))}function p(t,n){var i;try{if(t===n)throw new TypeError("A promises callback cannot return that same promise.");if(n&&("function"==typeof n||"object"==typeof n)){var e=n.then;if("function"==typeof e)return e.call(n,function(e){i||(i=!0,n!==e?f(t,e):m(t,e))},function(e){i||(i=!0,v(t,e))}),!0}}catch(e){return i||v(t,e),!0}return!1}function f(e,t){e!==t&&p(e,t)||m(e,t)}function m(e,t){e.state_===i&&(e.state_=s,e.data_=t,u(w,e))}function v(e,t){e.state_===i&&(e.state_=s,e.data_=t,u(C,e))}function g(e){var t=e.then_;e.then_=y;for(var n=0;n<t.length;n++)h(t[n])}function w(e){e.state_=o,g(e)}function C(e){e.state_=r,g(e)}function b(e){if("function"!=typeof e)throw new TypeError("Promise constructor takes a function argument");if(!(this instanceof b))throw new TypeError("Failed to construct 'Promise': Please use the 'new' operator, this object constructor cannot be called as a function.");this.then_=[],function(e,t){function n(e){v(t,e)}try{e(function(e){f(t,e)},n)}catch(e){n(e)}}(e,this)}}(window);var t="v1.0.7. Built at 16/06/2020 10:44:43",h=Element.prototype.matches||Element.prototype.matchesSelector||Element.prototype.webkitMatchesSelector||Element.prototype.mozMatchesSelector||Element.prototype.msMatchesSelector||Element.prototype.oMatchesSelector,E=function(e,t){return new E.init(e,t)};E.version=t,E.fn=E.prototype={version:t,constructor:E,length:0,uid:"",push:[].push,sort:[].sort,splice:[].splice,indexOf:[].indexOf,reverse:[].reverse},E.extend=E.fn.extend=function(){var e,t,n=arguments[0]||{},i=1,s=arguments.length;for("object"!=typeof n&&"function"!=typeof n&&(n={}),i===s&&(n=this,i--);i<s;i++)if(null!=(e=arguments[i]))for(t in e)c(e,t)&&(n[t]=e[t]);return n},E.assign=function(){var e,t,n=arguments[0]||{},i=1,s=arguments.length;for("object"!=typeof n&&"function"!=typeof n&&(n={}),i===s&&(n=this,i--);i<s;i++)if(null!=(e=arguments[i]))for(t in e)c(e,t)&&e[t]!==y&&(n[t]=e[t]);return n};function d(){return Date.now()}function p(e){var t=document.createElement("script");if(t.type="text/javascript",I(e))return E(t);var n=E(e)[0];return n.src?t.src=n.src:t.textContent=n.innerText,document.body.appendChild(t),n.parentNode&&n.parentNode.removeChild(n),t}E.extend({intervalId:-1,intervalQueue:[],intervalTicking:!1,intervalTickId:null,setInterval:function(e,t){var n=this;if(this.intervalId++,this.intervalQueue.push({id:this.intervalId,fn:e,interval:t,lastTime:d()}),!this.intervalTicking){var i=function(){n.intervalTickId=requestAnimationFrame(i),E.each(n.intervalQueue,function(){var e=this;(e.interval<17||d()-e.lastTime>=e.interval)&&(e.fn(),e.lastTime=d())})};this.intervalTicking=!0,i()}return this.intervalId},clearInterval:function(e){for(var t=0;t<this.intervalQueue.length;t++)if(e===this.intervalQueue[t].id){this.intervalQueue.splice(t,1);break}0===this.intervalQueue.length&&(cancelAnimationFrame(this.intervalTickId),this.intervalTicking=!1)},setTimeout:function(e,t){var n=this,i=this.setInterval(function(){n.clearInterval(i),e()},t);return i},clearTimeout:function(e){return this.clearInterval(e)}}),E.fn.extend({index:function(e){var t,n=-1;return 0===this.length||I(t=I(e)?this[0]:e instanceof E&&0<e.length?e[0]:"string"==typeof e?E(e)[0]:y)||t&&t.parentNode&&E.each(t.parentNode.children,function(e){this===t&&(n=e)}),n},get:function(e){return e===y?this.items():e<0?this[e+this.length]:this[e]},eq:function(e){return!I(e)&&0<this.length?E.extend(E(this.get(e)),{_prevObj:this}):this},is:function(t){var n=!1;return 0!==this.length&&(t instanceof E?this.same(t):(":selected"===t?this.each(function(){this.selected&&(n=!0)}):":checked"===t?this.each(function(){this.checked&&(n=!0)}):":visible"===t?this.each(function(){o(this)&&(n=!0)}):":hidden"===t?this.each(function(){var e=getComputedStyle(this);"hidden"!==this.getAttribute("type")&&!this.hidden&&"none"!==e.display&&"hidden"!==e.visibility&&0!==parseInt(e.opacity)||(n=!0)}):"string"==typeof t&&-1===[":selected"].indexOf(t)?this.each(function(){h.call(this,t)&&(n=!0)}):a(t)?this.each(function(){var e=this;E.each(t,function(){e===this&&(n=!0)})}):"object"==typeof t&&1===t.nodeType&&this.each(function(){this===t&&(n=!0)}),n))},same:function(e){var t=!0;return e instanceof E||(e=E(e)),this.length===e.length&&(this.each(function(){-1===e.items().indexOf(this)&&(t=!1)}),t)},last:function(){return this.eq(this.length-1)},first:function(){return this.eq(0)},odd:function(){var e=this.filter(function(e,t){return t%2==0});return E.extend(e,{_prevObj:this})},even:function(){var e=this.filter(function(e,t){return t%2!=0});return E.extend(e,{_prevObj:this})},filter:function(e){if("string"==typeof e){var t=e;e=function(e){return h.call(e,t)}}return E.extend(E.merge(E(),[].filter.call(this,e)),{_prevObj:this})},find:function(e){var t,n=[];return e instanceof E?e:(t=0===this.length?this:(this.each(function(){void 0!==this.querySelectorAll&&(n=n.concat([].slice.call(this.querySelectorAll(e))))}),E.merge(E(),n)),E.extend(t,{_prevObj:this}))},contains:function(e){return 0<this.find(e).length},children:function(t){var e,n=[];return t instanceof E?t:(this.each(function(){for(e=0;e<this.children.length;e++)1===this.children[e].nodeType&&n.push(this.children[e])}),n=t?n.filter(function(e){return h.call(e,t)}):n,E.extend(E.merge(E(),n),{_prevObj:this}))},parent:function(t){var e=[];if(0!==this.length)return t instanceof E?t:(this.each(function(){this.parentNode&&-1===e.indexOf(this.parentNode)&&e.push(this.parentNode)}),e=t?e.filter(function(e){return h.call(e,t)}):e,E.extend(E.merge(E(),e),{_prevObj:this}))},parents:function(t){var n=[];if(0!==this.length)return t instanceof E?t:(this.each(function(){for(var e=this.parentNode;e;)1===e.nodeType&&-1===n.indexOf(e)&&(I(t)?n.push(e):h.call(e,t)&&n.push(e)),e=e.parentNode}),E.extend(E.merge(E(),n),{_prevObj:this}))},siblings:function(t){var n=[];if(0!==this.length)return t instanceof E?t:(this.each(function(){var e=this;e.parentNode&&E.each(e.parentNode.children,function(){e!==this&&n.push(this)})}),t&&(n=n.filter(function(e){return h.call(e,t)})),E.extend(E.merge(E(),n),{_prevObj:this}))},_siblingAll:function(t,n){var i=[];if(0!==this.length)return n instanceof E?n:(this.each(function(){for(var e=this;e&&(e=e[t]);)i.push(e)}),n&&(i=i.filter(function(e){return h.call(e,n)})),E.extend(E.merge(E(),i),{_prevObj:this}))},_sibling:function(t,n){var i=[];if(0!==this.length)return n instanceof E?n:(this.each(function(){var e=this[t];e&&1===e.nodeType&&i.push(e)}),n&&(i=i.filter(function(e){return h.call(e,n)})),E.extend(E.merge(E(),i),{_prevObj:this}))},prev:function(e){return this._sibling("previousElementSibling",e)},next:function(e){return this._sibling("nextElementSibling",e)},prevAll:function(e){return this._siblingAll("previousElementSibling",e)},nextAll:function(e){return this._siblingAll("nextElementSibling",e)},closest:function(t){var n=[];if(0!==this.length)return t instanceof E?t:t?(this.each(function(){for(var e=this;e&&e;){if(h.call(e,t))return void n.push(e);e=e.parentElement}}),E.extend(E.merge(E(),n.reverse()),{_prevObj:this})):this.parent(t)},has:function(e){var t=[];if(0!==this.length)return this.each(function(){0<E(this).children(e).length&&t.push(this)}),E.extend(E.merge(E(),t),{_prevObj:this})},back:function(e){var t;if(!0===e)for(t=this._prevObj;t&&t._prevObj;)t=t._prevObj;else t=this._prevObj?this._prevObj:this;return t}}),E.extend({script:function(e){if(I(e))return p();var t=E(e)[0];t.tagName&&"SCRIPT"===t.tagName?p(t):E.each(E(t).find("script"),function(){p(this)})}}),E.fn.extend({script:function(){return this.each(function(){E.script(this)})}}),E.fn.extend({_prop:function(e,t){return 1===arguments.length?0===this.length?y:this[0][e]:(I(t)&&(t=""),this.each(function(){this[e]=t,"innerHTML"===e&&E.script(this)}))},prop:function(e,t){return 1===arguments.length?this._prop(e):this._prop(e,void 0===t?"":t)},val:function(t){return I(t)?0===this.length?y:this[0].value:this.each(function(){var e=E(this);void 0!==this.value?this.value=t:e.html(t)})},html:function(e){var t=[];return 0===arguments.length?this._prop("innerHTML"):(e instanceof E?e.each(function(){t.push(E(this).outerHTML())}):t.push(e),this._prop("innerHTML",1===t.length&&I(t[0])?"":t.join("\n")),this)},outerHTML:function(){return this._prop("outerHTML")},text:function(e){return 0===arguments.length?this._prop("textContent"):this._prop("textContent",void 0===e?"":e)},innerText:function(e){return 0===arguments.length?this._prop("innerText"):this._prop("innerText",void 0===e?"":e)},empty:function(){return this.each(function(){void 0!==this.innerHTML&&(this.innerHTML="")})},clear:function(){return this.empty()}}),E.each=function(e,n){var t=0;if(a(e))[].forEach.call(e,function(e,t){n.apply(e,[t,e])});else for(var i in e)c(e,i)&&n.apply(e[i],[i,e[i],t++]);return e},E.fn.extend({each:function(e){return E.each(this,e)}});var f=function(e){this.expando="DATASET:UID:"+e.toUpperCase(),f.uid++};f.uid=-1,f.prototype={cache:function(e){var t=e[this.expando];return t||(t={},n(e)&&(e.nodeType?e[this.expando]=t:Object.defineProperty(e,this.expando,{value:t,configurable:!0}))),t},set:function(e,t,n){var i,s=this.cache(e);if("string"==typeof t)s[g(t)]=n;else for(i in t)c(t,i)&&(s[g(i)]=t[i]);return s},get:function(e,t){return t===y?this.cache(e):e[this.expando]&&e[this.expando][g(t)]},access:function(e,t,n){return t===y||t&&"string"==typeof t&&n===y?this.get(e,t):(this.set(e,t,n),n!==y?n:t)},remove:function(e,t){var n,i=e[this.expando];if(i!==y){if(t!==y){n=(t=Array.isArray(t)?t.map(g):(t=g(t))in i?[t]:t.match(/[^\x20\t\r\n\f]+/g)||[]).length;for(;n--;)delete i[t[n]]}return t!==y&&!C(i)||(e.nodeType?e[this.expando]=y:delete e[this.expando]),!0}},hasData:function(e){var t=e[this.expando];return t!==y&&!C(t)}};var b=new f("m4q");E.extend({hasData:function(e){return b.hasData(e)},data:function(e,t,n){return b.access(e,t,n)},removeData:function(e,t){return b.remove(e,t)},dataSet:function(e){if(I(e))return b;if(-1<["INTERNAL","M4Q"].indexOf(e.toUpperCase()))throw Error("You can not use reserved name for your dataset");return new f(e)}}),E.fn.extend({data:function(e,t){var n,i,s,a,o,r;if(0!==this.length){if(i=this[0],0!==arguments.length)return 1===arguments.length?((n=b.get(i,e))===y&&1===i.nodeType&&i.hasAttribute("data-"+e)&&(n=i.getAttribute("data-"+e)),n):this.each(function(){b.set(this,e,t)});if(this.length&&(s=b.get(i),1===i.nodeType))for(r=(a=i.attributes).length;r--;)a[r]&&0===(o=a[r].name).indexOf("data-")&&l(i,o=g(o.slice(5)),s[o]);return s}},removeData:function(e){return this.each(function(){b.remove(this,e)})},origin:function(e,t,n){if(0===this.length)return this;if(I(e)&&I(t))return E.data(this[0]);if(I(t)){var i=E.data(this[0],"origin-"+e);return I(i)?n:i}return this.data("origin-"+e,t),this}}),E.extend({uniqueId:function(e){var n=(new Date).getTime();return I(e)&&(e="m4q"),(""!==e?e+"-":"")+"xxxx-xxxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,function(e){var t=(n+16*Math.random())%16|0;return n=Math.floor(n/16),("x"===e?t:3&t|8).toString(16)})},toArray:function(e){var t,n=[];for(t=0;t<e.length;t++)n.push(e[t]);return n},import:function(e){var t=[];return this.each(e,function(){t.push(this)}),this.merge(E(),t)},merge:function(e,t){for(var n=+t.length,i=0,s=e.length;i<n;i++)e[s++]=t[i];return e.length=s,e},type:function(e){return Object.prototype.toString.call(e).replace(/^\[object (.+)]$/,"$1").toLowerCase()},sleep:function(e){for(e+=(new Date).getTime();new Date<e;);},isSelector:function(e){if("string"!=typeof e)return!1;if(-1!==e.indexOf("<"))return!1;try{E(e)}catch(e){return!1}return!0},remove:function(e){return E(e).remove()},camelCase:function(e){return g(e)},dashedName:function(e){return function(e){return e.replace(/([A-Z])/g,function(e){return"-"+e.toLowerCase()})}(e)},isPlainObject:function(e){return w(e)},isEmptyObject:function(e){return C(e)},isArrayLike:function(e){return a(e)},acceptData:function(e){return n(e)},not:function(e){return I(e)},parseUnit:function(e,t){return m(e,t)},getUnit:function(e,t){return v(e,t)},unit:function(e,t){return m(e,t)},isVisible:function(e){return o(e)},isHidden:function(e){return function(e){var t=getComputedStyle(e);return!o(e)||0==+t.opacity||e.hidden||"hidden"===t.visibility}(e)},matches:function(e,t){return h.call(e,t)},random:function(e,t){return 1===arguments.length&&a(e)?e[Math.floor(Math.random()*e.length)]:Math.floor(Math.random()*(t-e+1)+e)},strip:function(e,t){return function(e,t){return"string"!=typeof e?y:e.replace(t,"")}(e,t)},normName:function(e){return u(e)},hasProp:function(e,t){return c(e,t)},serializeToArray:function(e){var t=E(e)[0];if(t&&"FORM"===t.nodeName){var n,i,s=[];for(n=t.elements.length-1;0<=n;n-=1)if(""!==t.elements[n].name)switch(t.elements[n].nodeName){case"INPUT":switch(t.elements[n].type){case"checkbox":case"radio":t.elements[n].checked&&s.push(t.elements[n].name+"="+encodeURIComponent(t.elements[n].value));break;case"file":break;default:s.push(t.elements[n].name+"="+encodeURIComponent(t.elements[n].value))}break;case"TEXTAREA":s.push(t.elements[n].name+"="+encodeURIComponent(t.elements[n].value));break;case"SELECT":switch(t.elements[n].type){case"select-one":s.push(t.elements[n].name+"="+encodeURIComponent(t.elements[n].value));break;case"select-multiple":for(i=t.elements[n].options.length-1;0<=i;i-=1)t.elements[n].options[i].selected&&s.push(t.elements[n].name+"="+encodeURIComponent(t.elements[n].options[i].value))}break;case"BUTTON":switch(t.elements[n].type){case"reset":case"submit":case"button":s.push(t.elements[n].name+"="+encodeURIComponent(t.elements[n].value))}}return s}console.warn("Element is not a HTMLFromElement")},serialize:function(e){return E.serializeToArray(e).join("&")}}),E.fn.extend({items:function(){return E.toArray(this)}}),function(){if("function"==typeof window.CustomEvent)return;function e(e,t){t=t||{bubbles:!1,cancelable:!1,detail:null};var n=document.createEvent("CustomEvent");return n.initCustomEvent(e,t.bubbles,t.cancelable,t.detail),n}e.prototype=window.Event.prototype,window.CustomEvent=e}();var x=Event.prototype.stopPropagation,S=Event.prototype.preventDefault;Event.prototype.stopPropagation=function(){this.isPropagationStopped=!0,x.apply(this,arguments)},Event.prototype.preventDefault=function(){this.isPreventedDefault=!0,S.apply(this,arguments)},Event.prototype.stop=function(e){return e?this.stopImmediatePropagation():this.stopPropagation()},E.extend({events:[],eventHooks:{},eventUID:-1,setEventHandler:function(e){var t,n,i=-1;if(0<this.events.length)for(t=0;t<this.events.length;t++)if(null===this.events[t].handler){i=t;break}return n={element:e.el,event:e.event,handler:e.handler,selector:e.selector,ns:e.ns,id:e.id,options:e.options},-1===i?(this.events.push(n),this.events.length-1):(this.events[i]=n,i)},getEventHandler:function(e){return this.events[e]!==y&&null!==this.events[e]?(this.events[e]=null,this.events[e].handler):y},off:function(){return E.each(this.events,function(){this.element.removeEventListener(this.event,this.handler,!0)}),this.events=[],this},getEvents:function(){return this.events},getEventHooks:function(){return this.eventHooks},addEventHook:function(e,t,n){return I(n)&&(n="before"),E.each(s(e),function(){this.eventHooks[g(n+"-"+this)]=t}),this},removeEventHook:function(e,t){return I(t)&&(t="before"),E.each(s(e),function(){delete this.eventHooks[g(t+"-"+this)]}),this},removeEventHooks:function(e){var t=this;return I(e)?this.eventHooks={}:E.each(s(e),function(){delete t.eventHooks[g("before-"+this)],delete t.eventHooks[g("after-"+this)]}),this}}),E.fn.extend({on:function(e,l,c,d){if(0!==this.length)return"function"==typeof l&&(d=c,c=l,l=y),w(d)||(d={}),this.each(function(){var r=this;E.each(s(e),function(){var e,s,t,n=this.split("."),a=u(n[0]),o=d.ns?d.ns:n[1];E.eventUID++,e=function(e){var t=e.target,n=E.eventHooks[g("before-"+a)],i=E.eventHooks[g("after-"+a)];if("function"==typeof n&&n.call(t,e),l)for(;t&&t!==r;){if(h.call(t,l)&&(c.call(t,e),e.isPropagationStopped)){e.stopImmediatePropagation();break}t=t.parentNode}else c.call(r,e);"function"==typeof i&&i.call(t,e),d.once&&(s=+E(r).origin("event-"+e.type+(l?":"+l:"")+(o?":"+o:"")),isNaN(s)||E.events.splice(s,1))},Object.defineProperty(e,"name",{value:c.name&&""!==c.name?c.name:"func_event_"+a+"_"+E.eventUID}),t=a+(l?":"+l:"")+(o?":"+o:""),r.addEventListener(a,e,!C(d)&&d),s=E.setEventHandler({el:r,event:a,handler:e,selector:l,ns:o,id:E.eventUID,options:!C(d)&&d}),E(r).origin("event-"+t,s)})})},one:function(e,t,n,i){return w(i)||(i={}),i.once=!0,this.on.apply(this,[e,t,n,i])},off:function(e,o,r){return w(o)&&(r=o,o=null),w(r)||(r={}),I(e)||"all"===e.toLowerCase()?this.each(function(){var t=this;E.each(E.events,function(){var e=this;e.element===t&&(t.removeEventListener(e.event,e.handler,e.options),e.handler=null,E(t).origin("event-"+name+(e.selector?":"+e.selector:"")+(e.ns?":"+e.ns:""),null))})}):this.each(function(){var a=this;E.each(s(e),function(){var e,t,n=this.split("."),i=u(n[0]),s=r.ns?r.ns:n[1];e="event-"+i+(o?":"+o:"")+(s?":"+s:""),(t=E(a).origin(e))!==y&&E.events[t].handler&&(a.removeEventListener(i,E.events[t].handler,E.events[t].options),E.events[t].handler=null),E(a).origin(e,null)})})},trigger:function(e,t){return this.fire(e,t)},fire:function(e,t){var n,i;if(0!==this.length)return n=u(e),-1<["focus","blur"].indexOf(n)?(this[0][n](),this):("undefined"!=typeof CustomEvent?i=new CustomEvent(n,{bubbles:!0,cancelable:!0,detail:t}):((i=document.createEvent("Events")).detail=t,i.initEvent(n,!0,!0)),this.each(function(){this.dispatchEvent(i)}))}}),"blur focus resize scroll click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup contextmenu touchstart touchend touchmove touchcancel".split(" ").forEach(function(i){E.fn[i]=function(e,t,n){return 0<arguments.length?this.on(i,e,t,n):this.fire(i)}}),E.fn.extend({hover:function(e,t){return this.mouseenter(e).mouseleave(t||e)}}),E.ready=function(e,t){document.addEventListener("DOMContentLoaded",e,t||!1)},E.load=function(e){return E(window).on("load",e)},E.unload=function(e){return E(window).on("unload",e)},E.fn.extend({unload:function(e){return 0===this.length||this[0].self!==window?y:E.unload(e)}}),E.beforeunload=function(t){return"string"==typeof t?E(window).on("beforeunload",function(e){return e.returnValue=t}):E(window).on("beforeunload",t)},E.fn.extend({beforeunload:function(e){return 0===this.length||this[0].self!==window?y:E.beforeunload(e)}}),E.fn.extend({ready:function(e){if(this.length&&this[0]===document&&"function"==typeof e)return E.ready(e)}}),E.ajax=function(v){return new Promise(function(n,i){function s(e,t){"function"==typeof e&&e.apply(null,t)}function e(e){return-1!==["GET","JSON"].indexOf(e)}var t,a,o,r=new XMLHttpRequest,l=(v.method||"GET").toUpperCase(),c=[],d=!!I(v.async)||v.async,u=v.url;if(v.data instanceof HTMLFormElement){var h=v.data.getAttribute("action"),p=v.data.getAttribute("method");I(u)&&h&&""!==h.trim()&&(u=h),p&&""!==p.trim()&&(l=p.toUpperCase())}if(v.timeout&&(r.timeout=v.timeout),v.withCredentials&&(r.withCredentials=v.withCredentials),v.data instanceof HTMLFormElement)t=E.serialize(v.data);else if(v.data instanceof HTMLElement&&v.data.getAttribute("type")&&"file"===v.data.getAttribute("type").toLowerCase()){var f=v.data.getAttribute("name");t=new FormData;for(var m=0;m<v.data.files.length;m++)t.append(f,v.data.files[m])}else w(v.data)?(a=v.data,o=[],E.each(a,function(e,t){var n=function(e){return"string"==typeof e||"boolean"==typeof e||"number"==typeof e}(t)?t:JSON.stringify(t);o.push(e+"="+n)}),t=o.join("&")):v.data instanceof FormData?t=v.data:"string"==typeof v.data?t=v.data:(t=new FormData).append("_data",JSON.stringify(v.data));e(l)&&(u+="string"==typeof t?"?"+t:C(t)?"":"?"+JSON.stringify(t)),r.open(l,u,d,v.user,v.password),v.headers&&E.each(v.headers,function(e,t){r.setRequestHeader(e,t),c.push(e)}),e(l)||-1===c.indexOf("Content-type")&&!1!==v.contentType&&r.setRequestHeader("Content-type","application/x-www-form-urlencoded"),r.send(t),r.addEventListener("load",function(e){if(4===r.readyState&&r.status<300){var t=v.returnValue&&"xhr"===v.returnValue?r:r.response;if(v.parseJson)try{t=JSON.parse(t)}catch(e){t={}}s(n,[t]),s(v.onSuccess,[e,r])}else s(i,[r]),s(v.onFail,[e,r]);s(v.onLoad,[e,r])}),E.each(["readystatechange","error","timeout","progress","loadstart","loadend","abort"],function(){var t=g("on-"+("readystatechange"===this?"state":this));r.addEventListener(t,function(e){s(v[t],[e,r])})})})},["get","post","put","patch","delete","json"].forEach(function(a){E[a]=function(e,t,n){var i=a.toUpperCase(),s={method:"JSON"===i?"GET":i,url:e,data:t,parseJson:"JSON"===i};return E.ajax(E.extend({},s,n))}}),E.fn.extend({load:function(e,t,n){var i=this;return this.length&&this[0].self===window?E.load(e):E.get(e,t,n).then(function(e){i.each(function(){this.innerHTML=e})})}}),E.fn.extend({style:function(e,t){var n;function i(e,t,n){return-1<["scrollLeft","scrollTop"].indexOf(t)?E(e)[t]():getComputedStyle(e,n)[t]}if("string"==typeof e&&0===this.length)return y;if(0===this.length)return this;if(n=this[0],I(e)||"all"===e)return getComputedStyle(n,t);var s={},a=e.split(", ").map(function(e){return(""+e).trim()});return 1===a.length?i(n,a[0],t):(E.each(a,function(){s[this]=i(n,this,t)}),s)},removeStyleProperty:function(e){if(I(e)||0===this.length)return this;var t=e.split(", ").map(function(e){return(""+e).trim()});return this.each(function(){var e=this;E.each(t,function(){e.style.removeProperty(this)})})},css:function(e,t){return"string"==typeof(e=e||"all")&&I(t)?this.style(e):this.each(function(){var n=this;"object"==typeof e?E.each(e,function(e,t){r(n,e,t)}):"string"==typeof e&&r(n,e,t)})},scrollTop:function(e){return I(e)?0===this.length?y:this[0]===window?pageYOffset:this[0].scrollTop:this.each(function(){this.scrollTop=e})},scrollLeft:function(e){return I(e)?0===this.length?y:this[0]===window?pageXOffset:this[0].scrollLeft:this.each(function(){this.scrollLeft=e})}}),E.fn.extend({addClass:function(){},removeClass:function(){},toggleClass:function(){},containsClass:function(e){return this.hasClass(e)},hasClass:function(e){var t=!1,n=e.split(" ").filter(function(e){return""!==(""+e).trim()});return!I(e)&&(this.each(function(){var e=this;E.each(n,function(){!t&&e.classList&&e.classList.contains(this)&&(t=!0)})}),t)},clearClasses:function(){return this.each(function(){this.className=""})},cls:function(e){return 0===this.length?y:e?this[0].className.split(" "):this[0].className},removeClassBy:function(n){return this.each(function(){var e=E(this),t=e.cls(!0);E.each(t,function(){-1<this.indexOf(n)&&e.removeClass(this)})})}}),["add","remove","toggle"].forEach(function(i){E.fn[i+"Class"]=function(n){return I(n)||""===(""+n).trim()?this:this.each(function(){var e=this,t=void 0!==e.classList;E.each(n.split(" ").filter(function(e){return""!==(""+e).trim()}),function(){t&&e.classList[i](this)})})}}),E.parseHTML=function(e,t){var n,i,s,a,o=[];if("string"!=typeof e)return[];if(e=e.trim(),(n=(s=document.implementation.createHTMLDocument("")).createElement("base")).href=document.location.href,s.head.appendChild(n),a=s.body,i=/^<([a-z][^\/\0>:\x20\t\r\n\f]*)[\x20\t\r\n\f]*\/?>(?:<\/\1>|)$/i.exec(e))o.push(document.createElement(i[1]));else{a.innerHTML=e;for(var r=0;r<a.childNodes.length;r++)o.push(a.childNodes[r])}return!t||t instanceof E||!w(t)||E.each(o,function(){for(var e in t)c(t,e)&&this.setAttribute(e,t[e])}),o},E.fn.extend({_size:function(e,t){if(0!==this.length){if(I(t)){var n=this[0];if("height"===e)return n===window?window.innerHeight:n===document?n.body.clientHeight:parseInt(getComputedStyle(n).height);if("width"===e)return n===window?window.innerWidth:n===document?n.body.clientWidth:parseInt(getComputedStyle(n).width)}return this.each(function(){this!==window&&this!==document&&(this.style[e]=isNaN(t)?t:t+"px")})}},height:function(e){return this._size("height",e)},width:function(e){return this._size("width",e)},_sizeOut:function(s,a){var e,t,n,i;if(0!==this.length)return I(a)||"boolean"==typeof a?(t=(e=this[0])["width"===s?"offsetWidth":"offsetHeight"],n=getComputedStyle(e),i=t+parseInt(n["width"===s?"margin-left":"margin-top"])+parseInt(n["width"===s?"margin-right":"margin-bottom"]),!0===a?i:t):this.each(function(){if(this!==window&&this!==document){var e,t=getComputedStyle(this),n="width"===s?parseInt(t["border-left-width"])+parseInt(t["border-right-width"]):parseInt(t["border-top-width"])+parseInt(t["border-bottom-width"]),i="width"===s?parseInt(t["padding-left"])+parseInt(t["padding-right"]):parseInt(t["padding-top"])+parseInt(t["padding-bottom"]);e=E(this)[s](a)[s]()-n-i,this.style[s]=e+"px"}})},outerWidth:function(e){return this._sizeOut("width",e)},outerHeight:function(e){return this._sizeOut("height",e)},padding:function(e){if(0!==this.length){var t=getComputedStyle(this[0],e);return{top:parseInt(t["padding-top"]),right:parseInt(t["padding-right"]),bottom:parseInt(t["padding-bottom"]),left:parseInt(t["padding-left"])}}},margin:function(e){if(0!==this.length){var t=getComputedStyle(this[0],e);return{top:parseInt(t["margin-top"]),right:parseInt(t["margin-right"]),bottom:parseInt(t["margin-bottom"]),left:parseInt(t["margin-left"])}}},border:function(e){if(0!==this.length){var t=getComputedStyle(this[0],e);return{top:parseInt(t["border-top-width"]),right:parseInt(t["border-right-width"]),bottom:parseInt(t["border-bottom-width"]),left:parseInt(t["border-left-width"])}}}}),E.fn.extend({offset:function(a){var e;return I(a)?0===this.length?y:{top:(e=this[0].getBoundingClientRect()).top+pageYOffset,left:e.left+pageXOffset}:this.each(function(){var e=E(this),t=a.top,n=a.left,i=getComputedStyle(this).position,s=e.offset();"static"===i&&e.css("position","relative"),-1===["absolute","fixed"].indexOf(i)&&(t-=s.top,n-=s.left),e.css({top:t,left:n})})},position:function(e){var t,n,i=0,s=0;return!I(e)&&"boolean"==typeof e||(e=!1),0===this.length?y:(t=this[0],n=getComputedStyle(t),e&&(i=parseInt(n["margin-left"]),s=parseInt(n["margin-top"])),{left:t.offsetLeft-i,top:t.offsetTop-s})},left:function(e,t){if(0!==this.length)return I(e)?this.position(t).left:"boolean"==typeof e?(t=e,this.position(t).left):this.each(function(){E(this).css({left:e})})},top:function(e,t){if(0!==this.length)return I(e)?this.position(t).top:"boolean"==typeof e?(t=e,this.position(t).top):this.each(function(){E(this).css({top:e})})},coord:function(){return 0===this.length?y:this[0].getBoundingClientRect()},pos:function(){if(0!==this.length)return{top:parseInt(E(this[0]).style("top")),left:parseInt(E(this[0]).style("left"))}}}),E.fn.extend({attr:function(e,t){var n={};return 0===this.length&&0===arguments.length?y:this.length&&0===arguments.length?(E.each(this[0].attributes,function(){n[this.nodeName]=this.nodeValue}),n):"string"==typeof e&&t===y?this.length&&1===this[0].nodeType&&this[0].hasAttribute(e)?this[0].getAttribute(e):y:this.each(function(){var n=this;w(e)?E.each(e,function(e,t){n.setAttribute(e,t)}):n.setAttribute(e,t)})},removeAttr:function(e){var t;return I(e)?this.each(function(){var e=this;E.each(this.attributes,function(){e.removeAttribute(this)})}):(t="string"==typeof e?e.split(",").map(function(e){return e.trim()}):e,this.each(function(){var e=this;E.each(t,function(){e.hasAttribute(this)&&e.removeAttribute(this)})}))},toggleAttr:function(e,t){return this.each(function(){I(t)?this.removeAttribute(e):this.setAttribute(e,t)})},id:function(e){return this.length?E(this[0]).attr("id",e):y}}),E.extend({meta:function(e){return I(e)?E("meta"):E("meta[name='$name']".replace("$name",e))},metaBy:function(e){return I(e)?E("meta"):E("meta[$name]".replace("$name",e))},doctype:function(){return E("doctype")},html:function(){return E("html")},head:function(){return E("html").find("head")},body:function(){return E("body")},document:function(){return E(document)},window:function(){return E(window)},charset:function(e){var t=E("meta[charset]");return e&&t.attr("charset",e),t.attr("charset")}}),E.extend({proxy:function(e,t){return"function"!=typeof e?y:e.bind(t)},bind:function(e,t){return this.proxy(e,t)}}),[Element.prototype,Document.prototype,DocumentFragment.prototype].forEach(function(e){["append","prepend"].forEach(function(t){c(e,t)||Object.defineProperty(e,t,{configurable:!0,enumerable:!0,writable:!0,value:function(){var e=Array.prototype.slice.call(arguments),n=document.createDocumentFragment();e.forEach(function(e){var t=e instanceof Node;n.appendChild(t?e:document.createTextNode(String(e)))}),"prepend"===t?this.insertBefore(n,this.firstChild):this.appendChild(n)}})})});function T(e){var t;return"string"==typeof e?t=E.isSelector(e)?E(e):E.parseHTML(e):e instanceof HTMLElement?t=[e]:a(e)&&(t=e),t}E.fn.extend({append:function(e){var i=T(e);return this.each(function(t,n){E.each(i,function(){if(n!==this){var e=0===t?this:this.cloneNode(!0);E.script(e),e.tagName&&"SCRIPT"!==e.tagName&&n.append(e)}})})},appendTo:function(e){var t=T(e);return this.each(function(){var n=this;E.each(t,function(e,t){n!==this&&t.append(0===e?n:n.cloneNode(!0))})})},prepend:function(e){var i=T(e);return this.each(function(t,n){E.each(i,function(){if(n!==this){var e=0===t?this:this.cloneNode(!0);E.script(e),e.tagName&&"SCRIPT"!==e.tagName&&n.prepend(e)}})})},prependTo:function(e){var t=T(e);return this.each(function(){var n=this;E.each(t,function(e,t){n!==this&&E(t).prepend(0===e?n:n.cloneNode(!0))})})},insertBefore:function(e){var t=T(e);return this.each(function(){var n=this;E.each(t,function(e){if(n!==this){var t=this.parentNode;t&&t.insertBefore(0===e?n:n.cloneNode(!0),this)}})})},insertAfter:function(e){var t=T(e);return this.each(function(){var i=this;E.each(t,function(e,t){if(i!==this){var n=this.parentNode;n&&n.insertBefore(0===e?i:i.cloneNode(!0),t.nextSibling)}})})},after:function(e){return this.each(function(){"string"==typeof e?this.insertAdjacentHTML("afterend",e):E(e).insertAfter(this)})},before:function(e){return this.each(function(){"string"==typeof e?this.insertAdjacentHTML("beforebegin",e):E(e).insertBefore(this)})},clone:function(i,s){var a=[];return I(i)&&(i=!1),I(s)&&(s=!1),this.each(function(){var e,t=this.cloneNode(i),n=E(t);s&&E.hasData(this)&&(e=E(this).data(),E.each(e,function(e,t){n.data(e,t)})),a.push(t)}),E.merge(E(),a)},import:function(e){var t=[];return I(e)&&(e=!1),this.each(function(){t.push(document.importNode(this,e))}),E.merge(E(),t)},adopt:function(){var e=[];return this.each(function(){e.push(document.adoptNode(this))}),E.merge(E(),e)},remove:function(t){var e,n,i=0,s=[];if(0!==this.length){for(n=t?this.filter(function(e){return h.call(e,t)}):this.items();null!=(e=n[i]);i++)e.parentNode&&(s.push(e.parentNode.removeChild(e)),E.removeData(e));return E.merge(E(),s)}},wrap:function(e){if(0!==this.length){var n=E(T(e));if(n.length){var i=[];return this.each(function(){var e,t;for((t=n.clone(!0,!0)).insertBefore(this),e=t;e.children().length;)e=e.children().eq(0);e.append(this),i.push(t)}),E(i)}}},wrapAll:function(e){var t,n,i;if(0!==this.length&&(t=E(T(e))).length){for((n=t.clone(!0,!0)).insertBefore(this[0]),i=n;i.children().length;)i=i.children().eq(0);return this.each(function(){i.append(this)}),n}},wrapInner:function(e){if(0!==this.length){var i=E(T(e));if(i.length){var s=[];return this.each(function(){var e=E(this),t=e.html(),n=i.clone(!0,!0);e.html(n.html(t)),s.push(n)}),E(s)}}}}),E.extend({animation:{duration:1e3,ease:"linear",elements:{}}}),"object"==typeof window.setupAnimation&&E.each(window.setupAnimation,function(e,t){void 0===E.animation[e]||I(t)||(E.animation[e]=t)});var k=["translateX","translateY","translateZ","rotate","rotateX","rotateY","rotateZ","scale","scaleX","scaleY","scaleZ","skew","skewX","skewY"],_=["opacity","zIndex"],M=["opacity","volume"],D=["scrollLeft","scrollTop"],A=["opacity","volume"];function O(e){return e instanceof HTMLElement||e instanceof SVGElement}function P(n,e,i){E.each(e,function(e,t){!function(e,t,n,i,s){I(s)&&(s=!1),t=g(t),s&&(n=parseInt(n)),O(e)?void 0!==e[t]?e[t]=n:e.style[t]="transform"===t||-1<t.toLowerCase().indexOf("color")?n:n+i:e[t]=n}(n,e,t[0]+t[2]*i,t[3],t[4])})}function N(e){if(!O(e))return{};for(var t,n=e.style.transform||"",i=/(\w+)\(([^)]*)\)/g,s={};t=i.exec(n);)s[t[1]]=t[2];return s}function R(e){return/^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(e||"#000000").slice(1).map(function(e){return parseInt(e,16)})}function L(e){return"#"===e[0]&&4===e.length?"#"+e.replace(/^#?([a-f\d])([a-f\d])([a-f\d])$/i,function(e,t,n,i){return t+t+n+n+i+i}):"#"===e[0]?e:"#"+e}function B(e,t,n){P(e,t.props,n),function(e,n,o){var r=[],t=N(e);E.each(n,function(e,t){var n=t[0],i=t[1],s=t[2],a=t[3];(-1<(e=""+e).indexOf("rotate")||-1<e.indexOf("skew"))&&""===a&&(a="deg"),-1<e.indexOf("scale")&&(a=""),-1<e.indexOf("translate")&&""===a&&(a="px"),"turn"===a?r.push(e+"("+i*o+a+")"):r.push(e+"("+(n+s*o)+a+")")}),E.each(t,function(e,t){n[e]===y&&r.push(e+"("+t+")")}),e.style.transform=r.join(" ")}(e,t.transform,n),function(a,e,o){E.each(e,function(e,t){var n,i,s=[0,0,0];for(n=0;n<3;n++)s[n]=Math.floor(t[0][n]+t[2][n]*o);i="rgb("+s.join(",")+")",a.style[e]=i})}(e,t.color,n)}function V(a,e,o){var r,l,c,d,u,h,p={props:{},transform:{},color:{}},f=N(a);return I(o)&&(o="normal"),E.each(e,function(e,t){var n=-1<k.indexOf(""+e),i=-1<_.indexOf(""+e),s=-1<(""+e).toLowerCase().indexOf("color");if(Array.isArray(t)&&1===t.length&&(t=t[0]),c=Array.isArray(t)?(l=s?R(L(t[0])):m(t[0]),s?R(L(t[1])):m(t[1])):(l=n?f[e]||0:s?function(e,t){return getComputedStyle(e)[t].replace(/[^\d.,]/g,"").split(",").map(function(e){return parseInt(e)})}(a,e):function(e,t,n){return void 0!==e[t]?-1<D.indexOf(t)?"scrollLeft"===t?e===window?pageXOffset:e.scrollLeft:e===window?pageYOffset:e.scrollTop:e[t]||0:e.style[t]||getComputedStyle(e,n)[t]}(a,e),l=s?l:m(l),s?R(t):m(function(e,t){var n=/^(\*=|\+=|-=)/.exec(e);if(!n)return e;var i=v(e)||0,s=parseFloat(t),a=parseFloat(e.replace(n[0],""));switch(n[0][0]){case"+":return s+a+i;case"-":return s-a+i;case"*":return s*a+i;case"/":return s/a+i}}(t,Array.isArray(l)?l[0]:l))),-1<A.indexOf(""+e)&&l[0]===c[0]&&(l[0]=0<c[0]?0:1),"reverse"===o&&(h=l,l=c,c=h),u=a instanceof HTMLElement&&""===c[1]&&!i&&!n?"px":c[1],s)for(d=[0,0,0],r=0;r<3;r++)d[r]=c[r]-l[r];else d=c[0]-l[0];n?p.transform[e]=[l[0],c[0],d,u]:s?p.color[e]=[l,c,d,u]:p.props[e]=[l[0],c[0],d,u,-1===M.indexOf(""+e)]}),p}function H(e,t,n){return Math.min(Math.max(e,t),n)}var F={linear:function(){return function(e){return e}}};F.default=F.linear;var z={Sine:function(){return function(e){return 1-Math.cos(e*Math.PI/2)}},Circ:function(){return function(e){return 1-Math.sqrt(1-e*e)}},Back:function(){return function(e){return e*e*(3*e-2)}},Bounce:function(){return function(e){for(var t,n=4;e<((t=Math.pow(2,--n))-1)/11;);return 1/Math.pow(4,3-n)-7.5625*Math.pow((3*t-2)/22-e,2)}},Elastic:function(e,t){I(e)&&(e=1),I(t)&&(t=.5);var n=H(e,1,10),i=H(t,.1,2);return function(e){return 0===e||1===e?e:-n*Math.pow(2,10*(e-1))*Math.sin((e-1-i/(2*Math.PI)*Math.asin(1/n))*(2*Math.PI)/i)}}};["Quad","Cubic","Quart","Quint","Expo"].forEach(function(e,t){z[e]=function(){return function(e){return Math.pow(e,t+2)}}}),Object.keys(z).forEach(function(e){var i=z[e];F["easeIn"+e]=i,F["easeOut"+e]=function(t,n){return function(e){return 1-i(t,n)(1-e)}},F["easeInOut"+e]=function(t,n){return function(e){return e<.5?i(t,n)(2*e)/2:1-i(t,n)(-2*e+2)/2}}});var j={id:null,el:null,draw:{},dur:E.animation.duration,ease:E.animation.ease,loop:0,pause:0,dir:"normal",defer:0,onFrame:function(){},onDone:function(){}};function U(_){return new Promise(function(e){var s,t,n=this,i=E.assign({},j,_),a=i.id,o=i.el,r=i.draw,l=i.dur,c=i.ease,d=i.loop,u=i.onFrame,h=i.onDone,p=i.pause,f=i.dir,m=i.defer,v={},g="linear",w=[],C=F.linear,b="alternate"===f?"normal":f,y=!1,x=a||+performance.now()*Math.pow(10,14);if(I(o))throw new Error("Unknown element!");if("string"==typeof o&&(o=document.querySelector(o)),"function"!=typeof r&&"object"!=typeof r)throw new Error("Unknown draw object. Must be a function or object!");0===l&&(l=1),"alternate"===f&&"number"==typeof d&&(d*=2),C="string"==typeof c?(t=/\(([^)]+)\)/.exec(c),g=c.split("(")[0],w=t?t[1].split(",").map(function(e){return parseFloat(e)}):[],F[g]||F.linear):"function"==typeof c?c:F.linear,E.animation.elements[x]={element:o,id:null,stop:0,pause:0,loop:0};function S(){"object"==typeof r&&(v=V(o,r,b)),s=performance.now(),E.animation.elements[x].loop+=1,E.animation.elements[x].id=requestAnimationFrame(k)}function T(){cancelAnimationFrame(E.animation.elements[x].id),delete E.animation.elements[a],"function"==typeof h&&h.apply(o),e(n)}var k=function(e){var t,n,i=E.animation.elements[x].stop;if(0<i)return 2===i&&("function"==typeof r?r.bind(o)(1,1):B(o,v,1)),void T();1<(n=(e-s)/l)&&(n=1),n<0&&(n=0),t=C.apply(null,w)(n),"function"==typeof r?r.bind(o)(n,t):B(o,v,t),"function"==typeof u&&u.apply(o,[n,t]),n<1&&(E.animation.elements[x].id=requestAnimationFrame(k)),1===parseInt(n)&&(d?("alternate"===f&&(b="normal"===b?"reverse":"normal"),"boolean"==typeof d?setTimeout(function(){S()},p):d>E.animation.elements[x].loop?setTimeout(function(){S()},p):T()):"alternate"!==f||y?T():(b="normal"===b?"reverse":"normal",y=!0,S()))};0<m?setTimeout(function(){S()},m):S()})}function q(e,t){I(t)&&(t=!0),E.animation.elements[e].stop=!0===t?2:1}E.easing={},E.extend(E.easing,F),E.extend({animate:function(e){var t,n,i,s,a;return 1<arguments.length?(t=E(e)[0],n=arguments[1],i=arguments[2]||E.animation.duration,s=arguments[3]||E.animation.ease,a=arguments[4],"function"==typeof i&&(a=i,s=E.animation.ease,i=E.animation.duration),"function"==typeof s&&(a=s,s=E.animation.ease),U({el:t,draw:n,dur:i,ease:s,onDone:a})):U(e)},stop:q,chain:function e(t,n){if(I(n)&&(n=!1),!Array.isArray(t))return console.warn("Chain array is not defined!"),!1;t.reduce(function(e,t){return e.then(function(){return U(t)})},Promise.resolve()).then(function(){n&&e(t,"boolean"==typeof n?n:--n)})}}),E.fn.extend({animate:function(e){var t,n,i,s,a=this,o=e;return!Array.isArray(e)&&(1<arguments.length||1===arguments.length&&void 0===e.draw)?(t=e,n=arguments[1]||E.animation.duration,i=arguments[2]||E.animation.ease,s=arguments[3],"function"==typeof n&&(s=n,n=E.animation.duration,i=E.animation.ease),"function"==typeof i&&(s=i,i=E.animation.ease),this.each(function(){return E.animate({el:this,draw:t,dur:n,ease:i,onDone:s})})):Array.isArray(e)?(E.each(e,function(){var e=this;a.each(function(){e.el=this,E.animate(e)})}),this):this.each(function(){o.el=this,E.animate(o)})},chain:function(t,n){return this.each(function(){var e=this;E.each(t,function(){this.el=e}),E.chain(t,n)})},stop:function(i){var e=E.animation.elements;return this.each(function(){var n=this;E.each(e,function(e,t){t.element===n&&q(e,i)})})}}),E.extend({hidden:function(e,t,n){return e=E(e)[0],"string"==typeof t&&(t="true"===t.toLowerCase()),"function"==typeof t&&(n=t,t=!e.hidden),e.hidden=t,"function"==typeof n&&(E.bind(n,e),n.call(e,arguments)),this},hide:function(e,t){var n=E(e);return e.style.display&&n.origin("display",e.style.display?e.style.display:getComputedStyle(e,null).display),e.style.display="none","function"==typeof t&&(E.bind(t,e),t.call(e,arguments)),this},show:function(e,t){var n=E(e).origin("display",y,"block");return e.style.display=n?"none"===n?"block":n:"",0===parseInt(e.style.opacity)&&(e.style.opacity="1"),"function"==typeof t&&(E.bind(t,e),t.call(e,arguments)),this},visible:function(e,t,n){return t===y&&(t=!0),e.style.visibility=t?"visible":"hidden","function"==typeof n&&(E.bind(n,e),n.call(e,arguments)),this},toggle:function(e,t){var n="none"!==getComputedStyle(e,null).display?"hide":"show";return E[n](e,t)}}),E.fn.extend({hide:function(){var e;return E.each(arguments,function(){"function"==typeof this&&(e=this)}),this.each(function(){E.hide(this,e)})},show:function(){var e;return E.each(arguments,function(){"function"==typeof this&&(e=this)}),this.each(function(){E.show(this,e)})},visible:function(e,t){return this.each(function(){E.visible(this,e,t)})},toggle:function(e){return this.each(function(){E.toggle(this,e)})},hidden:function(e,t){return this.each(function(){E.hidden(this,e,t)})}}),E.extend({fx:{off:!1}}),E.fn.extend({fadeIn:function(i,s,a){return this.each(function(){var e=this,t=E(e);if(!(!o(e)||o(e)&&0==+t.style("opacity")))return this;I(i)&&I(s)&&I(a)?(a=null,i=E.animation.duration):"function"==typeof i&&(a=i,i=E.animation.duration),"function"==typeof s&&(a=s,s=E.animation.ease),E.fx.off&&(i=0);var n=t.origin("display",y,"block");return e.style.opacity="0",e.style.display=n,E.animate({el:e,draw:{opacity:1},dur:i,ease:s,onDone:function(){"function"==typeof a&&E.proxy(a,this)()}})})},fadeOut:function(t,n,i){return this.each(function(){var e=E(this);if(o(this))return I(t)&&I(n)&&I(i)?(i=null,t=E.animation.duration):"function"==typeof t&&(i=t,t=E.animation.duration),"function"==typeof n&&(i=n,n=E.animation.ease),e.origin("display",e.style("display")),E.animate({el:this,draw:{opacity:0},dur:t,ease:n,onDone:function(){this.style.display="none","function"==typeof i&&E.proxy(i,this)()}})})},slideUp:function(n,i,s){return this.each(function(){var e,t=E(this);if(0!==t.height())return I(n)&&I(i)&&I(s)?(s=null,n=E.animation.duration):"function"==typeof n&&(s=n,n=E.animation.duration),"function"==typeof i&&(s=i,i=E.animation.ease),e=t.height(),t.origin("height",e),t.origin("display",E(this).style("display")),t.css({overflow:"hidden"}),E.animate({el:this,draw:{height:0},dur:n,ease:i,onDone:function(){t.hide().removeStyleProperty("overflow, height"),"function"==typeof s&&E.proxy(s,this)()}})})},slideDown:function(s,a,o){return this.each(function(){var e,t,n=this,i=E(n);return I(s)&&I(a)&&I(o)?(o=null,s=E.animation.duration):"function"==typeof s&&(o=s,s=E.animation.duration),"function"==typeof a&&(o=a,a=E.animation.ease),i.show().visible(!1),e=+i.origin("height",y,i.height()),0===parseInt(e)&&(e=n.scrollHeight),t=i.origin("display",i.style("display"),"block"),i.height(0).visible(!0),i.css({overflow:"hidden",display:"none"===t?"block":t}),E.animate({el:n,draw:{height:e},dur:s,ease:a,onDone:function(){E(n).removeStyleProperty("overflow, height, visibility"),"function"==typeof o&&E.proxy(o,this)()}})})},moveTo:function(e,t,n,i,s){var a={top:t,left:e};return"function"==typeof n&&(s=n,n=E.animation.duration,i=E.animation.ease),"function"==typeof i&&(s=i,i=E.animation.ease),this.each(function(){E.animate({el:this,draw:a,dur:n,ease:i,onDone:s})})},centerTo:function(t,n,i,s,a){return"function"==typeof i&&(a=i,i=E.animation.duration,s=E.animation.ease),"function"==typeof s&&(a=s,s=E.animation.ease),this.each(function(){var e={left:t-this.clientWidth/2,top:n-this.clientHeight/2};E.animate({el:this,draw:e,dur:i,ease:s,onDone:a})})},colorTo:function(e,t,n,i){var s={color:e};return"function"==typeof t&&(i=t,t=E.animation.duration,n=E.animation.ease),"function"==typeof n&&(i=n,n=E.animation.ease),this.each(function(){E.animate({el:this,draw:s,dur:t,ease:n,onDone:i})})},backgroundTo:function(e,t,n,i){var s={backgroundColor:e};return"function"==typeof t&&(i=t,t=E.animation.duration,n=E.animation.ease),"function"==typeof n&&(i=n,n=E.animation.ease),this.each(function(){E.animate({el:this,draw:s,dur:t,ease:n,onDone:i})})}}),E.init=function(e,t){var n,i;if(this.uid=E.uniqueId(),!e)return this;if("function"==typeof e)return E.ready(e);if("string"==typeof e&&"document"===e&&(e=document),"string"==typeof e&&"body"===e&&(e=document.body),"string"==typeof e&&"html"===e&&(e=document.documentElement),"string"==typeof e&&"doctype"===e&&(e=document.doctype),e&&(e.nodeType||e.self===window))return this[0]=e,this.length=1,this;if(e instanceof E)return i=E(),E.each(e,function(){i.push(this)}),i;if(a(e))return i=E(),E.each(e,function(){E(this).each(function(){i.push(this)})}),i;if("object"==typeof e)return e;if("string"==typeof e){if("#"===(e=e.trim())||"."===e)return console.warn("Selector can't be # or ."),this;1===(n=E.parseHTML(e,t)).length&&3===n[0].nodeType?[].push.apply(this,document.querySelectorAll(e)):E.merge(this,n)}if(t!==y){var s=this;t instanceof E?this.each(function(){E(t).append(s)}):t instanceof HTMLElement&&E(t).append(s)}return this},E.init.prototype=E.fn;var W=window.$;E.Promise=Promise,window.m4q=E,void 0===window.$&&(window.$=E),E.global=function(){W=window.$,window.$=E},E.noConflict=function(){return window.$===E&&(window.$=W),E}}(window),function(e){"use strict";var t=e.meta("metro4:init").attr("content"),n=e.meta("metro4:locale").attr("content"),i=e.meta("metro4:week_start").attr("content"),s=e.meta("metro4:date_format").attr("content"),a=e.meta("metro4:date_format_input").attr("content"),o=e.meta("metro4:animation_duration").attr("content"),r=e.meta("metro4:callback_timeout").attr("content"),l=e.meta("metro4:timeout").attr("content"),c=e.meta("metro4:scroll_multiple").attr("content"),d=e.meta("metro4:cloak").attr("content"),u=e.meta("metro4:cloak_duration").attr("content"),h=e.meta("metro4:global_common").attr("content");void 0===window.METRO_GLOBAL_COMMON&&(window.METRO_GLOBAL_COMMON=void 0!==h&&JSON.parse(h));var p=e.meta("metro4:jquery").attr("content");window.jquery_present="undefined"!=typeof jQuery,void 0===window.METRO_JQUERY&&(window.METRO_JQUERY=void 0===p||JSON.parse(p)),window.useJQuery=window.jquery_present&&window.METRO_JQUERY;var f=e.meta("metro4:about").attr("content");void 0===window.METRO_SHOW_ABOUT&&(window.METRO_SHOW_ABOUT=void 0===f||JSON.parse(f));var m=e.meta("metro4:compile").attr("content");void 0===window.METRO_SHOW_COMPILE_TIME&&(window.METRO_SHOW_COMPILE_TIME=void 0===m||JSON.parse(m)),void 0===window.METRO_INIT&&(window.METRO_INIT=void 0===t||JSON.parse(t)),void 0===window.METRO_DEBUG&&(window.METRO_DEBUG=!0),void 0===window.METRO_WEEK_START&&(window.METRO_WEEK_START=void 0!==i?parseInt(i):0),void 0===window.METRO_DATE_FORMAT&&(window.METRO_DATE_FORMAT=void 0!==s?s:"%Y-%m-%d"),void 0===window.METRO_DATE_FORMAT_INPUT&&(window.METRO_DATE_FORMAT_INPUT=void 0!==a?a:"%Y-%m-%d"),void 0===window.METRO_LOCALE&&(window.METRO_LOCALE=void 0!==n?n:"en-US"),void 0===window.METRO_ANIMATION_DURATION&&(window.METRO_ANIMATION_DURATION=void 0!==o?parseInt(o):100),void 0===window.METRO_CALLBACK_TIMEOUT&&(window.METRO_CALLBACK_TIMEOUT=void 0!==r?parseInt(r):500),void 0===window.METRO_TIMEOUT&&(window.METRO_TIMEOUT=void 0!==l?parseInt(l):2e3),void 0===window.METRO_SCROLL_MULTIPLE&&(window.METRO_SCROLL_MULTIPLE=void 0!==c?parseInt(c):20),void 0===window.METRO_CLOAK_REMOVE&&(window.METRO_CLOAK_REMOVE=void 0!==d?(""+d).toLowerCase():"fade"),void 0===window.METRO_CLOAK_DURATION&&(window.METRO_CLOAK_DURATION=void 0!==u?parseInt(u):300),void 0===window.METRO_HOTKEYS_FILTER_CONTENT_EDITABLE&&(window.METRO_HOTKEYS_FILTER_CONTENT_EDITABLE=!0),void 0===window.METRO_HOTKEYS_FILTER_INPUT_ACCEPTING_ELEMENTS&&(window.METRO_HOTKEYS_FILTER_INPUT_ACCEPTING_ELEMENTS=!0),void 0===window.METRO_HOTKEYS_FILTER_TEXT_INPUTS&&(window.METRO_HOTKEYS_FILTER_TEXT_INPUTS=!0),void 0===window.METRO_HOTKEYS_BUBBLE_UP&&(window.METRO_HOTKEYS_BUBBLE_UP=!1),void 0===window.METRO_THROWS&&(window.METRO_THROWS=!0),window.METRO_MEDIA=[]}(m4q),function(e){ true?!(__WEBPACK_AMD_DEFINE_FACTORY__ = (e),
				__WEBPACK_AMD_DEFINE_RESULT__ = (typeof __WEBPACK_AMD_DEFINE_FACTORY__ === 'function' ?
				(__WEBPACK_AMD_DEFINE_FACTORY__.call(exports, __webpack_require__, exports, module)) :
				__WEBPACK_AMD_DEFINE_FACTORY__),
				__WEBPACK_AMD_DEFINE_RESULT__ !== undefined && (module.exports = __WEBPACK_AMD_DEFINE_RESULT__)):undefined}(function(){"use strict";var u=m4q;if("undefined"==typeof m4q)throw new Error("Metro 4 requires m4q helper!");if(!("MutationObserver"in window))throw new Error("Metro 4 requires MutationObserver!");function o(e){return"string"!=typeof e?void 0:e.replace(/-/g,"").toLowerCase()}var s="ontouchstart"in window||0<navigator.MaxTouchPoints||0<navigator.msMaxTouchPoints,h={version:"4.3.10",compileTime:"12/07/2020 20:25:57",buildNumber:"749",isTouchable:s,fullScreenEnabled:document.fullscreenEnabled,sheet:null,controlsPosition:{INSIDE:"inside",OUTSIDE:"outside"},groupMode:{ONE:"one",MULTI:"multi"},aspectRatio:{HD:"hd",SD:"sd",CINEMA:"cinema"},fullScreenMode:{WINDOW:"window",DESKTOP:"desktop"},position:{TOP:"top",BOTTOM:"bottom",LEFT:"left",RIGHT:"right",TOP_RIGHT:"top-right",TOP_LEFT:"top-left",BOTTOM_LEFT:"bottom-left",BOTTOM_RIGHT:"bottom-right",LEFT_BOTTOM:"left-bottom",LEFT_TOP:"left-top",RIGHT_TOP:"right-top",RIGHT_BOTTOM:"right-bottom"},popoverEvents:{CLICK:"click",HOVER:"hover",FOCUS:"focus"},stepperView:{SQUARE:"square",CYCLE:"cycle",DIAMOND:"diamond"},listView:{LIST:"list",CONTENT:"content",ICONS:"icons",ICONS_MEDIUM:"icons-medium",ICONS_LARGE:"icons-large",TILES:"tiles",TABLE:"table"},events:{click:"click",start:s?"touchstart":"mousedown",stop:s?"touchend":"mouseup",move:s?"touchmove":"mousemove",enter:s?"touchstart":"mouseenter",startAll:"mousedown touchstart",stopAll:"mouseup touchend",moveAll:"mousemove touchmove",leave:"mouseleave",focus:"focus",blur:"blur",resize:"resize",keyup:"keyup",keydown:"keydown",keypress:"keypress",dblclick:"dblclick",input:"input",change:"change",cut:"cut",paste:"paste",scroll:"scroll",mousewheel:"mousewheel",inputchange:"change input propertychange cut paste copy drop",dragstart:"dragstart",dragend:"dragend",dragenter:"dragenter",dragover:"dragover",dragleave:"dragleave",drop:"drop",drag:"drag"},keyCode:{BACKSPACE:8,TAB:9,ENTER:13,SHIFT:16,CTRL:17,ALT:18,BREAK:19,CAPS:20,ESCAPE:27,SPACE:32,PAGEUP:33,PAGEDOWN:34,END:35,HOME:36,LEFT_ARROW:37,UP_ARROW:38,RIGHT_ARROW:39,DOWN_ARROW:40,COMMA:188},media_queries:{FS:"(min-width: 0px)",XS:"(min-width: 360px)",SM:"(min-width: 576px)",MD:"(min-width: 768px)",LG:"(min-width: 992px)",XL:"(min-width: 1200px)",XXL:"(min-width: 1452px)"},media_sizes:{FS:0,XS:360,SM:576,LD:640,MD:768,LG:992,XL:1200,XXL:1452},media_mode:{FS:"fs",XS:"xs",SM:"sm",MD:"md",LG:"lg",XL:"xl",XXL:"xxl"},media_modes:["fs","xs","sm","md","lg","xl","xxl"],actions:{REMOVE:1,HIDE:2},hotkeys:{},locales:{},utils:{},colors:{},dialog:null,pagination:null,md5:null,storage:null,export:null,animations:null,cookie:null,template:null,about:function(){var e="<h3>About</h3><hr><div><b>Metro 4</b> - v"+h.version+". "+h.showCompileTime()+"</div><div><b>M4Q</b> - "+m4q.version+"</div>";h.infobox.create(e)},info:function(){console.info("Metro 4 - v"+h.version+". "+h.showCompileTime()),console.info("m4q - "+m4q.version)},showCompileTime:function(){return"Built at: "+h.compileTime},aboutDlg:function(){alert("Metro 4 - v"+h.version+". "+h.showCompileTime())},ver:function(){return h.version},build:function(){return h.build},compile:function(){return h.compileTime},observe:function(){new MutationObserver(function(e){e.map(function(e){if("attributes"===e.type&&"data-role"!==e.attributeName)if("data-hotkey"===e.attributeName)h.initHotkeys([e.target],!0);else{var t=u(e.target),n=t.data("metroComponent"),i=e.attributeName,s=t.attr(i),a=e.oldValue;void 0!==n&&(t.fire("attr-change",{attr:i,newValue:s,oldValue:a,__this:t[0]}),u.each(n,function(){var e=h.getPlugin(t,this);e&&"function"==typeof e.changeAttribute&&e.changeAttribute(i,s,a)}))}else if("childList"===e.type&&0<e.addedNodes.length){var o,r,l,c=[],d=e.addedNodes;if(d.length){for(o=0;o<d.length;o++)l=d[o],void 0!==(r=u(l)).attr("data-role")&&c.push(l),u.each(r.find("[data-role]"),function(){-1===c.indexOf(this)&&c.push(this)});c.length&&h.initWidgets(c,"observe")}}})}).observe(u("html")[0],{childList:!0,attributes:!0,subtree:!0})},init:function(){var e=u("[data-role]"),t=u("[data-hotkey]"),n=u("html"),i=this;window.METRO_SHOW_ABOUT&&h.info(!0),!0==s?n.addClass("metro-touch-device"):n.addClass("metro-no-touch-device"),h.sheet=this.utils.newCssSheet(),window.METRO_MEDIA=[],u.each(h.media_queries,function(e,t){i.utils.media(t)&&window.METRO_MEDIA.push(h.media_mode[e])}),h.observe(),h.initHotkeys(t),h.initWidgets(e,"init"),"fade"!==window.METRO_CLOAK_REMOVE?(u(".m4-cloak").removeClass("m4-cloak"),u(window).fire("metro-initiated")):u(".m4-cloak").animate({draw:{opacity:1},dur:300,onDone:function(){u(".m4-cloak").removeClass("m4-cloak"),u(window).fire("metro-initiated")}})},initHotkeys:function(e,i){u.each(e,function(){var e=u(this),t=!!e.attr("data-hotkey")&&e.attr("data-hotkey").toLowerCase(),n=!!e.attr("data-hotkey-func")&&e.attr("data-hotkey-func");!1!==t&&(!0===e.data("hotKeyBonded")&&!0!==i||(h.hotkeys[t]=[this,n],e.data("hotKeyBonded",!0),e.fire("hot-key-bonded",{__this:e[0],hotkey:t,fn:n})))})},initWidgets:function(e){var a=this;u.each(e,function(){var s=u(this);s.data("role").split(/\s*,\s*/).map(function(t){var e=a.utils.$(),n=o(t);if(void 0!==e.fn[n]&&void 0===s.attr("data-role-"+n))try{e.fn[n].call(s),s.attr("data-role-"+n,!0);var i=s.data("metroComponent");void 0===i?i=[n]:i.push(n),s.data("metroComponent",i),s.fire("create",{__this:s[0],name:n}),u(document).fire("component-create",{element:s[0],name:n})}catch(e){throw console.error("Error creating component "+t+" for ",s[0]),e}})})},plugin:function(e,n){function t(t){t.fn[i]=function(e){return this.each(function(){t.data(this,i,Object.create(n).init(e,this))})}}var i=o(e);t(m4q),window.useJQuery&&t(jQuery)},destroyPlugin:function(e,t){var n,i,s=u(e),a=o(t);void 0!==(n=h.getPlugin(s,a))?"function"==typeof n.destroy?(n.destroy(),i=s.data("metroComponent"),this.utils.arrayDelete(i,a),s.data("metroComponent",i),u.removeData(s[0],a),s.removeAttr("data-role-"+a)):console.warn("Component "+t+" can not be destroyed: method destroy not found."):console.warn("Component "+t+" can not be destroyed: the element is not a Metro 4 component.")},destroyPluginAll:function(e){var t=u(e),n=t.data("metroComponent");void 0!==n&&0<n.length&&u.each(n,function(){h.destroyPlugin(t[0],this)})},noop:function(){},noop_true:function(){return!0},noop_false:function(){return!1},requestFullScreen:function(e){e.mozRequestFullScreen?e.mozRequestFullScreen():e.webkitRequestFullScreen?e.webkitRequestFullScreen():e.msRequestFullscreen?e.msRequestFullscreen():e.requestFullscreen().catch(function(e){console.warn("Error attempting to enable full-screen mode: "+e.message+" "+e.name)})},exitFullScreen:function(){document.mozCancelFullScreen?document.mozCancelFullScreen():document.webkitCancelFullScreen?document.webkitCancelFullScreen():document.msExitFullscreen?document.msExitFullscreen():document.exitFullscreen().catch(function(e){console.warn("Error attempting to disable full-screen mode: "+e.message+" "+e.name)})},inFullScreen:function(){return void 0!==(document.fullscreenElement||document.webkitFullscreenElement||document.mozFullScreenElement||document.msFullscreenElement)},$:function(){return window.useJQuery?jQuery:m4q},get$el:function(e){return h.$()(u(e)[0])},getPlugin:function(e,t){var n=o(t),i=h.get$el(e);return i.length?i.data(n):void 0},makePlugin:function(e,t,n){var i=o(t),s=h.get$el(e);return s.length&&"function"==typeof s[i]?s[i](n):void 0},Component:function(e,t){var n=o(e),l=h.utils,i=u.extend({name:n},{_super:function(e,t,n,i){var s=this;this.elem=e,this.element=u(e),this.options=u.extend({},n,t),this._setOptionsFromDOM(),this._runtime(),i&&"object"==typeof i&&u.each(i,function(e,t){s[e]=t}),this._createExec()},_setOptionsFromDOM:function(){var e=this.element,i=this.options;u.each(e.data(),function(t,n){if(t in i)try{i[t]=JSON.parse(n)}catch(e){i[t]=n}})},_runtime:function(){var e,t=this.element;t.attr("data-role-"+this.name)||(t.attr("data-role-"+this.name,!0),t.attr("data-role",this.name),void 0===(e=t.data("metroComponent"))?e=[this.name]:e.push(this.name),t.data("metroComponent",e))},_createExec:function(){var e=this,t=this.options[this.name+"Deferred"];t?setTimeout(function(){e._create()},t):e._create()},_fireEvent:function(e,t,n,i){var s,a=this.element,o=this.options,r=e.camelCase().capitalize();return s=(t=u.extend({},t,{__this:a[0]}))?Object.values(t):{},n&&(console.warn(n),console.warn("Event: on"+e.camelCase().capitalize()),console.warn("Data: ",t),console.warn("Element: ",a[0])),!0!==i&&a.fire(r.toLowerCase(),t),l.exec(o["on"+r],s,a[0])}},t);return h.plugin(n,i),i}};return u(window).on(h.events.resize,function(){window.METRO_MEDIA=[],u.each(h.media_queries,function(e,t){h.utils.media(t)&&window.METRO_MEDIA.push(h.media_mode[e])})}),window.Metro=h,!0===window.METRO_INIT&&u(function(){h.init()}),h}),function(e,t){m4q.extend(e.locales,{"cn-ZH":{calendar:{months:["一月","二月","三月","四月","五月","六月","七月","八月","九月","十月","十一月","十二月","1月","2月","3月","4月","5月","6月","7月","8月","9月","10月","11月","12月"],days:["星期日","星期一","星期二","星期三","星期四","星期五","星期六","日","一","二","三","四","五","六","周日","周一","周二","周三","周四","周五","周六"],time:{days:"天",hours:"时",minutes:"分",seconds:"秒",month:"月",day:"日",year:"年"}},buttons:{ok:"确认",cancel:"取消",done:"完成",today:"今天",now:"现在",clear:"清除",help:"帮助",yes:"是",no:"否",random:"随机",save:"保存",reset:"重啟"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"da-DK":{calendar:{months:["Januar","Februar","Marts","April","Maj","Juni","Juli","August","September","Oktober","November","December","Jan","Feb","Mar","Apr","Maj","Jun","Jul","Aug","Sep","Okt","Nov","Dec"],days:["Søndag","Mandag","Tirsdag","Onsdag","Torsdag","Fredag","Lørdag","Sø","Ma","Ti","On","To","Fr","Lø","Søn","Man","Tir","Ons","Tor","Fre","Lør"],time:{days:"DAGE",hours:"TIMER",minutes:"MIN",seconds:"SEK",month:"MON",day:"DAG",year:"ÅR"}},buttons:{ok:"OK",cancel:"Annuller",done:"Færdig",today:"Idag",now:"Nu",clear:"Ryd",help:"Hjælp",yes:"Ja",no:"Nej",random:"Tilfældig",save:"Gem",reset:"Nulstil"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"de-DE":{calendar:{months:["Januar","Februar","März","April","Mai","Juni","Juli","August","September","Oktober","November","Dezember","Jan","Feb","Mär","Apr","Mai","Jun","Jul","Aug","Sep","Okt","Nov","Dez"],days:["Sonntag","Montag","Dienstag","Mittwoch","Donnerstag","Freitag","Samstag","So","Mo","Di","Mi","Do","Fr","Sa","Son","Mon","Die","Mit","Don","Fre","Sam"],time:{days:"TAGE",hours:"STD",minutes:"MIN",seconds:"SEK"}},buttons:{ok:"OK",cancel:"Abbrechen",done:"Fertig",today:"Heute",now:"Jetzt",clear:"Löschen",help:"Hilfe",yes:"Ja",no:"Nein",random:"Zufällig",save:"Speichern",reset:"Zurücksetzen"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"en-US":{calendar:{months:["January","February","March","April","May","June","July","August","September","October","November","December","Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"],days:["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Su","Mo","Tu","We","Th","Fr","Sa","Sun","Mon","Tus","Wen","Thu","Fri","Sat"],time:{days:"DAYS",hours:"HOURS",minutes:"MINS",seconds:"SECS",month:"MON",day:"DAY",year:"YEAR"}},buttons:{ok:"OK",cancel:"Cancel",done:"Done",today:"Today",now:"Now",clear:"Clear",help:"Help",yes:"Yes",no:"No",random:"Random",save:"Save",reset:"Reset"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"es-MX":{calendar:{months:["Enero","Febrero","Marzo","Abril","Mayo","Junio","Julio","Agosto","Septiembre","Octubre","Noviembre","Diciembre","Ene","Feb","Mar","Abr","May","Jun","Jul","Ago","Sep","Oct","Nov","Dic"],days:["Domingo","Lunes","Martes","Miércoles","Jueves","Viernes","Sábado","Do","Lu","Ma","Mi","Ju","Vi","Sa","Dom","Lun","Mar","Mié","Jue","Vie","Sáb"],time:{days:"DÍAS",hours:"HORAS",minutes:"MINS",seconds:"SEGS",month:"MES",day:"DÍA",year:"AÑO"}},buttons:{ok:"Aceptar",cancel:"Cancelar",done:"Hecho",today:"Hoy",now:"Ahora",clear:"Limpiar",help:"Ayuda",yes:"Si",no:"No",random:"Aleatorio",save:"Salvar",reset:"Reiniciar"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"fr-FR":{calendar:{months:["Janvier","Février","Mars","Avril","Mai","Juin","Juillet","Août","Septembre","Octobre","Novembre","Décembre","Janv","Févr","Mars","Avr","Mai","Juin","Juil","Août","Sept","Oct","Nov","Déc"],days:["Dimanche","Lundi","Mardi","Mercredi","Jeudi","Vendredi","Samedi","Di","Lu","Ma","Me","Je","Ve","Sa","Dim","Lun","Mar","Mer","Jeu","Ven","Sam"],time:{days:"JOURS",hours:"HEURES",minutes:"MINS",seconds:"SECS",month:"MOIS",day:"JOUR",year:"ANNEE"}},buttons:{ok:"OK",cancel:"Annulé",done:"Fait",today:"Aujourd'hui",now:"Maintenant",clear:"Effacé",help:"Aide",yes:"Oui",no:"Non",random:"Aléatoire",save:"Sauvegarder",reset:"Réinitialiser"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"hu-HU":{calendar:{months:["Január","Február","Március","Április","Május","Június","Július","Augusztus","Szeptember","Október","November","December","Jan","Feb","Már","Ápr","Máj","Jún","Júl","Aug","Szep","Okt","Nov","Dec"],days:["Vasárnap","Hétfő","Kedd","Szerda","Csütörtök","Péntek","Szombat","V","H","K","Sz","Cs","P","Sz","Vas","Hét","Ke","Sze","Csü","Pén","Szom"],time:{days:"NAP",hours:"ÓRA",minutes:"PERC",seconds:"MP"}},buttons:{ok:"OK",cancel:"Mégse",done:"Kész",today:"Ma",now:"Most",clear:"Törlés",help:"Segítség",yes:"Igen",no:"Nem",random:"Véletlen",save:"Mentés",reset:"Visszaállítás"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"it-IT":{calendar:{months:["Gennaio","Febbraio","Marzo","Aprile","Maggio","Giugno","Luglio","Agosto","Settembre","Ottobre","Novembre","Dicembre","Gen","Feb","Mar","Apr","Mag","Giu","Lug","Ago","Set","Ott","Nov","Dic"],days:["Domenica","Lunedì","Martedì","Mercoledì","Giovedì","Venerdì","Sabato","Do","Lu","Ma","Me","Gi","Ve","Sa","Dom","Lun","Mar","Mer","Gio","Ven","Sab"],time:{days:"GIORNI",hours:"ORE",minutes:"MIN",seconds:"SEC",month:"MESE",day:"GIORNO",year:"ANNO"}},buttons:{ok:"OK",cancel:"Annulla",done:"Fatto",today:"Oggi",now:"Adesso",clear:"Cancella",help:"Aiuto",yes:"Sì",no:"No",random:"Random",save:"Salvare",reset:"Reset"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"pt-BR":{calendar:{months:["Janeiro","Fevereiro","Março","Abril","Maio","Junho","Julho","Agosto","Setembro","Outubro","Novembro","Dezembro","Jan","Fev","Mar","Abr","Maio","Jun","Jul","Ago","Set","Out","Nov","Dez"],days:["Domingo","Segunda","Terça","Quarta","Quinta","Sexta","Sábado","Do","Se","Te","Qa","Qi","Se","Sa","Dom","Seg","Ter","Qua","Qui","Sex","Sab"],time:{days:"DIAS",hours:"HORAS",minutes:"MINUTOS",seconds:"SEGUNDOS",month:"MÊS",day:"DIA",year:"ANO"}},buttons:{ok:"OK",cancel:"Cancelar",done:"Feito",today:"Hoje",now:"Agora",clear:"Limpar",help:"Ajuda",yes:"Sim",no:"Não",random:"Aleatório",save:"Salvar",reset:"Restaurar"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"ru-RU":{calendar:{months:["Январь","Февраль","Март","Апрель","Май","Июнь","Июль","Август","Сентябрь","Октябрь","Ноябрь","Декабрь","Янв","Фев","Мар","Апр","Май","Июн","Июл","Авг","Сен","Окт","Ноя","Дек"],days:["Воскресенье","Понедельник","Вторник","Среда","Четверг","Пятница","Суббота","Вс","Пн","Вт","Ср","Чт","Пт","Сб","Вос","Пон","Вто","Сре","Чет","Пят","Суб"],time:{days:"ДНИ",hours:"ЧАСЫ",minutes:"МИН",seconds:"СЕК"}},buttons:{ok:"ОК",cancel:"Отмена",done:"Готово",today:"Сегодня",now:"Сейчас",clear:"Очистить",help:"Помощь",yes:"Да",no:"Нет",random:"Случайно",save:"Сохранить",reset:"Сброс"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"tw-ZH":{calendar:{months:["一月","二月","三月","四月","五月","六月","七月","八月","九月","十月","十一月","十二月","1月","2月","3月","4月","5月","6月","7月","8月","9月","10月","11月","12月"],days:["星期日","星期一","星期二","星期三","星期四","星期五","星期六","日","一","二","三","四","五","六","週日","週一","週二","週三","週四","週五","週六"],time:{days:"天",hours:"時",minutes:"分",seconds:"秒",month:"月",day:"日",year:"年"}},buttons:{ok:"確認",cancel:"取消",done:"完成",today:"今天",now:"現在",clear:"清除",help:"幫助",yes:"是",no:"否",random:"隨機",save:"保存",reset:"重啟"}}})}(Metro),function(e,t){m4q.extend(e.locales,{"uk-UA":{calendar:{months:["Січень","Лютий","Березень","Квітень","Травень","Червень","Липень","Серпень","Вересень","Жовтень","Листопад","Грудень","Січ","Лют","Бер","Кві","Тра","Чер","Лип","Сер","Вер","Жов","Лис","Гру"],days:["Неділя","Понеділок","Вівторок","Середа","Четвер","П’ятниця","Субота","Нд","Пн","Вт","Ср","Чт","Пт","Сб","Нед","Пон","Вiв","Сер","Чет","Пят","Суб"],time:{days:"ДНІ",hours:"ГОД",minutes:"ХВИЛ",seconds:"СЕК"}},buttons:{ok:"ОК",cancel:"Відміна",done:"Готово",today:"Сьогодні",now:"Зараз",clear:"Очистити",help:"Допомога",yes:"Так",no:"Ні",random:"Випадково",save:"Зберегти",reset:"Скинути"}}})}(Metro),function(){"use strict";"function"!=typeof Array.shuffle&&(Array.prototype.shuffle=function(){for(var e,t,n=this.length;0!==n;)t=Math.floor(Math.random()*n),e=this[n-=1],this[n]=this[t],this[t]=e;return this}),"function"!=typeof Array.clone&&(Array.prototype.clone=function(){return this.slice(0)}),"function"!=typeof Array.unique&&(Array.prototype.unique=function(){for(var e=this.concat(),t=0;t<e.length;++t)for(var n=t+1;n<e.length;++n)e[t]===e[n]&&e.splice(n--,1);return e}),"function"!=typeof Array.from&&(Array.prototype.from=function(e){var t,n=[];if(void 0===e.length&&"object"==typeof e)return Object.values(e);if(void 0===e.length)throw new Error("Value can not be converted to array");for(t=0;t<e.length;t++)n.push(e[t]);return n}),"function"!=typeof Array.contains&&(Array.prototype.contains=function(e,t){return-1<this.indexOf(e,t)}),"function"!=typeof Array.includes&&(Array.prototype.includes=function(e,t){return-1<this.indexOf(e,t)})}(),function(f){"use strict";Date.prototype.getWeek=function(e){var t,n,i,s,a;return e=Utils.isValue(e)?"number"==typeof e?parseInt(e):0:METRO_WEEK_START,i=0<=(i=(n=new Date(this.getFullYear(),0,1)).getDay()-e)?i:i+7,s=Math.floor((this.getTime()-n.getTime()-6e4*(this.getTimezoneOffset()-n.getTimezoneOffset()))/864e5)+1,i<4?52<(a=Math.floor((s+i-1)/7)+1)&&(a=(t=0<=(t=new Date(this.getFullYear()+1,0,1).getDay()-e)?t:t+7)<4?1:53):a=Math.floor((s+i-1)/7),a},Date.prototype.getYear=function(){return this.getFullYear().toString().substr(-2)},Date.prototype.format=function(e,t){void 0===t&&(t="en-US");function i(){var e=new Date(a);return e.setDate(r-(o+6)%7+3),e}function s(e,t){return(""+(Math.pow(10,t)+e)).slice(1)}var n=(void 0!==f.locales&&void 0!==f.locales[t]?f.locales[t]:f.locales["en-US"]).calendar,a=this,o=a.getDay(),r=a.getDate(),l=a.getMonth(),c=a.getFullYear(),d=a.getHours(),u=n.days,h=n.months,p=[0,31,59,90,120,151,181,212,243,273,304,334];return e.replace(/(%[a-z])/gi,function(e){return{"%a":u[o].slice(0,3),"%A":u[o],"%b":h[l].slice(0,3),"%B":h[l],"%c":a.toUTCString(),"%C":Math.floor(c/100),"%d":s(r,2),dd:s(r,2),"%e":r,"%F":a.toISOString().slice(0,10),"%G":i().getFullYear(),"%g":(""+i().getFullYear()).slice(2),"%H":s(d,2),"%I":s((d+11)%12+1,2),"%j":s(p[l]+r+(1<l&&(c%4==0&&c%100!=0||c%400==0)?1:0),3),"%k":""+d,"%l":(d+11)%12+1,"%m":s(l+1,2),"%M":s(a.getMinutes(),2),"%p":d<12?"AM":"PM","%P":d<12?"am":"pm","%s":Math.round(a.getTime()/1e3),"%S":s(a.getSeconds(),2),"%u":o||7,"%V":function(){var e=i(),t=e.valueOf();e.setMonth(0,1);var n=e.getDay();return 4!==n&&e.setMonth(0,1+(4-n+7)%7),s(1+Math.ceil((t-e)/6048e5),2)}(),"%w":""+o,"%x":a.toLocaleDateString(),"%X":a.toLocaleTimeString(),"%y":(""+c).slice(2),"%Y":c,"%z":a.toTimeString().replace(/.+GMT([+-]\d+).+/,"$1"),"%Z":a.toTimeString().replace(/.+\((.+?)\)$/,"$1")}[e]||e})},Date.prototype.addHours=function(e){return this.setTime(this.getTime()+60*e*60*1e3),this},Date.prototype.addDays=function(e){return this.setDate(this.getDate()+e),this},Date.prototype.addMonths=function(e){return this.setMonth(this.getMonth()+e),this},Date.prototype.addYears=function(e){return this.setFullYear(this.getFullYear()+e),this}}(Metro),function(){"use strict";Number.prototype.format=function(e,t,n,i){var s="\\d(?=(\\d{"+(t||3)+"})+"+(0<e?"\\D":"$")+")",a=this.toFixed(Math.max(0,~~e));return(i?a.replace(".",i):a).replace(new RegExp(s,"g"),"$&"+(n||","))}}(),function(){"use strict";"function"!=typeof Object.create&&(Object.create=function(e){function t(){}return t.prototype=e,new t}),"function"!=typeof Object.values&&(Object.values=function(t){return Object.keys(t).map(function(e){return t[e]})})}(),function(w,e){"use strict";String.prototype.camelCase=function(){return e.camelCase(this)},String.prototype.dashedName=function(){return e.dashedName(this)},String.prototype.shuffle=function(){return function(e){for(var t,n,i=e.length;0!==i;)n=Math.floor(Math.random()*i),t=e[i-=1],e[i]=e[n],e[n]=t;return e}(this.split("")).join("")},String.prototype.capitalize=function(){return this.charAt(0).toUpperCase()+this.slice(1)},String.prototype.contains=function(){return!!~String.prototype.indexOf.apply(this,arguments)},"function"!=typeof String.includes&&(String.prototype.includes=function(){return!!~String.prototype.indexOf.apply(this,arguments)}),String.prototype.toDate=function(e,o){var t,n,i,s,a,r,l,c,d,u,h,p,f,m,v,g;o=o||"en-US";if(null==e||""===e)return new Date(this);if(t=this.replace(/[\/,.:\s]/g,"-"),n=e.toLowerCase().replace(/[^a-zA-Z0-9%]/g,"-").split("-"),i=t.split("-"),""===t.replace(/-/g,"").trim())return"Invalid Date";if(s=-1<n.indexOf("mm")?n.indexOf("mm"):n.indexOf("%m"),a=-1<n.indexOf("dd")?n.indexOf("dd"):n.indexOf("%d"),r=-1<n.indexOf("yyyy")?n.indexOf("yyyy"):-1<n.indexOf("yy")?n.indexOf("yy"):n.indexOf("%y"),l=-1<n.indexOf("hh")?n.indexOf("hh"):n.indexOf("%h"),c=-1<n.indexOf("ii")?n.indexOf("ii"):-1<n.indexOf("mi")?n.indexOf("mi"):n.indexOf("%i"),d=-1<n.indexOf("ss")?n.indexOf("ss"):n.indexOf("%s"),!(-1<s&&""!==i[s]))return"Invalid Date";if(isNaN(parseInt(i[s]))){if(i[s]=function(e){var t,n,i,s,a=w.locales;if(null==e)return-1;if(e=e.substr(0,3),void 0!==o&&"en-US"!==o&&void 0!==a&&void 0!==a[o]&&void 0!==a[o].calendar&&void 0!==a[o].calendar.months){for(n=a[o].calendar.months,s=12;s<n.length;s++)if(n[s].toLowerCase()===e.toLowerCase()){i=s-12;break}e=a["en-US"].calendar.months[i]}return t=Date.parse(e+" 1, 1972"),isNaN(t)?-1:new Date(t).getMonth()+1}(i[s]),-1===i[s])return"Invalid Date"}else if((g=parseInt(i[s]))<1||12<g)return"Invalid Date";return u=-1<r&&""!==i[r]?i[r]:null,h=-1<s&&""!==i[s]?i[s]:null,p=-1<a&&""!==i[a]?i[a]:null,f=-1<l&&""!==i[l]?i[l]:null,m=-1<c&&""!==i[c]?i[c]:null,v=-1<d&&""!==i[d]?i[d]:null,new Date(u,h-1,p,f,m,v)},String.prototype.toArray=function(e,n,i){return n=n||"string",i=null!=i&&i,(""+this).split(e=e||",").map(function(e){var t;switch(n){case"int":case"integer":t=isNaN(e)?e.trim():parseInt(e);break;case"number":case"float":t=isNaN(e)?e:parseFloat(e);break;case"date":t=i?e.toDate(i):new Date(e);break;default:t=e.trim()}return t})}}(Metro,m4q),function(s,o){"use strict";s.utils={isVisible:function(e){var t=o(e)[0];return"none"!==this.getStyleOne(t,"display")&&"hidden"!==this.getStyleOne(t,"visibility")&&null!==t.offsetParent},isUrl:function(e){return/^(\.\/|\.\.\/|ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@\-\/]))?/.test(e)},isTag:function(e){return/^<\/?[\w\s="/.':;#-\/\?]+>/gi.test(e)},isColor:function(e){return/(^#[0-9A-F]{6}$)|(^#[0-9A-F]{3}$)/i.test(e)},isEmbedObject:function(e){var t=!1;return o.each(["iframe","object","embed","video"],function(){"string"==typeof e&&e.toLowerCase()===this?t=!0:void 0!==e.nodeType&&e.tagName.toLowerCase()===this&&(t=!0)}),t},isVideoUrl:function(e){return/youtu\.be|youtube|vimeo/gi.test(e)},isDate:function(e,t){return!!this.isDateObject(e)||"Invalid Date"!==(this.isValue(t)?String(e).toDate(t):String(new Date(e)))},isDateObject:function(e){return"object"==typeof e&&void 0!==e.getMonth},isInt:function(e){return!isNaN(e)&&+e%1==0},isFloat:function(e){return!isNaN(e)&&+e%1!=0||/^\d*\.\d+$/.test(e)},isTouchDevice:function(){return"ontouchstart"in window||0<navigator.MaxTouchPoints||0<navigator.msMaxTouchPoints},isFunc:function(e){return this.isType(e,"function")},isObject:function(e){return this.isType(e,"object")},isArray:function(e){return Array.isArray(e)},isType:function(e,t){if(!this.isValue(e))return!1;if(typeof e===t)return e;if("tag"===(""+t).toLowerCase()&&this.isTag(e))return e;if("url"===(""+t).toLowerCase()&&this.isUrl(e))return e;if("array"===(""+t).toLowerCase()&&this.isArray(e))return e;if(this.isTag(e)||this.isUrl(e))return!1;if(typeof window[e]===t)return window[e];if("string"==typeof e&&-1===e.indexOf("."))return!1;if("string"==typeof e&&/[/\s([]+/gm.test(e))return!1;if("number"==typeof e&&"number"!==t.toLowerCase())return!1;var n,i=e.split("."),s=window;for(n=0;n<i.length;n++)s=s[i[n]];return typeof s===t&&s},$:function(){return window.useJQuery?jQuery:m4q},isMetroObject:function(e,t){var n=o(e),i=s.getPlugin(e,t);return 0===n.length?(console.warn(t+" "+e+" not found!"),!1):void 0!==i||(console.warn("Element not contain role "+t+'! Please add attribute data-role="'+t+'" to element '+e),!1)},isJQuery:function(e){return"undefined"!=typeof jQuery&&e instanceof jQuery},isM4Q:function(e){return"undefined"!=typeof m4q&&e instanceof m4q},isQ:function(e){return this.isJQuery(e)||this.isM4Q(e)},isIE11:function(){return!!window.MSInputMethodContext&&!!document.documentMode},embedObject:function(e){return"<div class='embed-container'>"+o(e)[0].outerHTML+"</div>"},embedUrl:function(e){return-1!==e.indexOf("youtu.be")&&(e="https://www.youtube.com/embed/"+e.split("/").pop()),"<div class='embed-container'><iframe src='"+e+"'></iframe></div>"},secondsToTime:function(e){var t=e%3600,n=t%60;return{h:Math.floor(e/3600),m:Math.floor(t/60),s:Math.ceil(n)}},hex2rgba:function(e,t){var n;if(t=isNaN(t)?1:t,/^#([A-Fa-f0-9]{3}){1,2}$/.test(e))return 3===(n=e.substring(1).split("")).length&&(n=[n[0],n[0],n[1],n[1],n[2],n[2]]),"rgba("+[(n="0x"+n.join(""))>>16&255,n>>8&255,255&n].join(",")+","+t+")";throw new Error("Hex2rgba error. Bad Hex value")},elementId:function(e){return e+"-"+(new Date).getTime()+o.random(1,1e3)},secondsToFormattedString:function(e){var t=parseInt(e,10),n=Math.floor(t/3600),i=Math.floor((t-3600*n)/60),s=t-3600*n-60*i;return n<10&&(n="0"+n),i<10&&(i="0"+i),s<10&&(s="0"+s),[n,i,s].join(":")},func:function(e){return new Function("a",e)},exec:function(e,t,n){var i;if(null==e)return!1;var s=this.isFunc(e);!1===s&&(s=this.func(e));try{i=s.apply(n,t)}catch(e){if(!(i=null)===METRO_THROWS)throw e}return i},isOutsider:function(e){var t,n=o(e),i=n.clone();return i.removeAttr("data-role").css({visibility:"hidden",position:"absolute",display:"block"}),n.parent().append(i),t=i[0].getBoundingClientRect(),i.remove(),0<=t.top&&0<=t.left&&t.bottom<=(window.innerHeight||document.documentElement.clientHeight)&&t.right<=(window.innerWidth||document.documentElement.clientWidth)},inViewport:function(e){var t=this.rect(e);return 0<=t.top&&0<=t.left&&t.bottom<=(window.innerHeight||document.documentElement.clientHeight)&&t.right<=(window.innerWidth||document.documentElement.clientWidth)},rect:function(e){return e.getBoundingClientRect()},getCursorPosition:function(e,t){var n=this.rect(e);return{x:this.pageXY(t).x-n.left-window.pageXOffset,y:this.pageXY(t).y-n.top-window.pageYOffset}},getCursorPositionX:function(e,t){return this.getCursorPosition(e,t).x},getCursorPositionY:function(e,t){return this.getCursorPosition(e,t).y},objectLength:function(e){return Object.keys(e).length},percent:function(e,t,n){if(0===e)return 0;var i=100*t/e;return!0===n?Math.round(i):Math.round(100*i)/100},objectShift:function(e){var t=0;return o.each(e,function(e){0===t?t=e:e<t&&(t=e)}),delete e[t],e},objectDelete:function(e,t){void 0!==e[t]&&delete e[t]},arrayDeleteByMultipleKeys:function(t,e){return e.forEach(function(e){delete t[e]}),t.filter(function(e){return void 0!==e})},arrayDelete:function(e,t){-1<e.indexOf(t)&&e.splice(e.indexOf(t),1)},arrayDeleteByKey:function(e,t){e.splice(t,1)},nvl:function(e,t){return null==e?t:e},objectClone:function(e){var t={};for(var n in e)o.hasProp(e,n)&&(t[n]=e[n]);return t},github:function(e,t){var n=this;o.json("https://api.github.com/repos/"+e).then(function(e){n.exec(t,[e])})},detectIE:function(){var e=window.navigator.userAgent,t=e.indexOf("MSIE ");if(0<t)return parseInt(e.substring(t+5,e.indexOf(".",t)),10);if(0<e.indexOf("Trident/")){var n=e.indexOf("rv:");return parseInt(e.substring(n+3,e.indexOf(".",n)),10)}var i=e.indexOf("Edge/");return 0<i&&parseInt(e.substring(i+5,e.indexOf(".",i)),10)},detectChrome:function(){return/Chrome/.test(navigator.userAgent)&&/Google Inc/.test(navigator.vendor)},encodeURI:function(e){return encodeURI(e).replace(/%5B/g,"[").replace(/%5D/g,"]")},pageHeight:function(){var e=document.body,t=document.documentElement;return Math.max(e.scrollHeight,e.offsetHeight,t.clientHeight,t.scrollHeight,t.offsetHeight)},cleanPreCode:function(e){Array.prototype.slice.call(document.querySelectorAll(e),0).forEach(function(e){var t=e.textContent.replace(/^[\r\n]+/,"").replace(/\s+$/g,"");if(/^\S/gm.test(t))e.textContent=t;else{for(var n,i,s,a=/^[\t ]+/gm,o=1e3;n=a.exec(t);)(s=n[0].length)<o&&(o=s,i=n[0]);1e3!==o&&(e.textContent=t.replace(new RegExp("^"+i,"gm"),"").trim())}})},coords:function(e){var t=o(e)[0].getBoundingClientRect();return{top:t.top+window.pageYOffset,left:t.left+window.pageXOffset}},positionXY:function(e,t){switch(t){case"client":return this.clientXY(e);case"screen":return this.screenXY(e);case"page":return this.pageXY(e);default:return{x:0,y:0}}},clientXY:function(e){return{x:e.changedTouches?e.changedTouches[0].clientX:e.clientX,y:e.changedTouches?e.changedTouches[0].clientY:e.clientY}},screenXY:function(e){return{x:e.changedTouches?e.changedTouches[0].screenX:e.screenX,y:e.changedTouches?e.changedTouches[0].screenY:e.screenY}},pageXY:function(e){return{x:e.changedTouches?e.changedTouches[0].pageX:e.pageX,y:e.changedTouches?e.changedTouches[0].pageY:e.pageY}},isRightMouse:function(e){return"which"in e?3===e.which:"button"in e?2===e.button:void 0},hiddenElementSize:function(e,t){var n,i,s=o(e).clone(!0);return s.removeAttr("data-role").css({visibility:"hidden",position:"absolute",display:"block"}),o("body").append(s),this.isValue(t)||(t=!1),n=s.outerWidth(t),i=s.outerHeight(t),s.remove(),{width:n,height:i}},getStyle:function(e,t){var n=o(e)[0];return window.getComputedStyle(n,t)},getStyleOne:function(e,t){return this.getStyle(e).getPropertyValue(t)},getTransformMatrix:function(e,t){var n=this.getStyleOne(e,"transform").replace("matrix(","").slice(0,-1).split(",");return!0!==t?{a:n[0],b:n[1],c:n[2],d:n[3],tx:n[4],ty:n[5]}:n},computedRgbToHex:function(e){var t,n=e.replace(/[^\d,]/g,"").split(","),i="#";for(t=0;t<3;t++){var s=parseInt(n[t]).toString(16);i+=1===s.length?"0"+s:s}return i},computedRgbToRgba:function(e,t){var n=e.replace(/[^\d,]/g,"").split(",");return void 0===t&&(t=1),n.push(t),"rgba("+n.join(",")+")"},computedRgbToArray:function(e){return e.replace(/[^\d,]/g,"").split(",")},hexColorToArray:function(e){var t;return/^#([A-Fa-f0-9]{3}){1,2}$/.test(e)?(3===(t=e.substring(1).split("")).length&&(t=[t[0],t[0],t[1],t[1],t[2],t[2]]),[(t="0x"+t.join(""))>>16&255,t>>8&255,255&t]):[0,0,0]},hexColorToRgbA:function(e,t){var n;return/^#([A-Fa-f0-9]{3}){1,2}$/.test(e)?(3===(n=e.substring(1).split("")).length&&(n=[n[0],n[0],n[1],n[1],n[2],n[2]]),"rgba("+[(n="0x"+n.join(""))>>16&255,n>>8&255,255&n,t||1].join(",")+")"):"rgba(0,0,0,1)"},getInlineStyles:function(e){var t,n,i={},s=o(e)[0];for(t=0,n=s.style.length;t<n;t++){var a=s.style[t];i[a]=s.style[a]}return i},updateURIParameter:function(e,t,n){var i=new RegExp("([?&])"+t+"=.*?(&|$)","i"),s=-1!==e.indexOf("?")?"&":"?";return e.match(i)?e.replace(i,"$1"+t+"="+n+"$2"):e+s+t+"="+n},getURIParameter:function(e,t){e||(e=window.location.href),t=t.replace(/[\[\]]/g,"\\$&");var n=new RegExp("[?&]"+t+"(=([^&#]*)|&|#|$)").exec(e);return n?n[2]?decodeURIComponent(n[2].replace(/\+/g," ")):"":null},getLocales:function(){return Object.keys(s.locales)},addLocale:function(e){s.locales=o.extend({},s.locales,e)},aspectRatioH:function(e,t){return"16/9"===t?9*e/16:"21/9"===t?9*e/21:"4/3"===t?3*e/4:void 0},aspectRatioW:function(e,t){return"16/9"===t?16*e/9:"21/9"===t?21*e/9:"4/3"===t?4*e/3:void 0},valueInObject:function(e,t){return-1<Object.values(e).indexOf(t)},keyInObject:function(e,t){return-1<Object.keys(e).indexOf(t)},inObject:function(e,t,n){return void 0!==e[t]&&e[t]===n},newCssSheet:function(e){var t=document.createElement("style");return void 0!==e&&t.setAttribute("media",e),t.appendChild(document.createTextNode("")),document.head.appendChild(t),t.sheet},addCssRule:function(e,t,n,i){"insertRule"in e?e.insertRule(t+"{"+n+"}",i):"addRule"in e&&e.addRule(t,n,i)},media:function(e){return window.matchMedia(e).matches},mediaModes:function(){return METRO_MEDIA},mediaExist:function(e){return-1<METRO_MEDIA.indexOf(e)},inMedia:function(e){return-1<METRO_MEDIA.indexOf(e)&&METRO_MEDIA.indexOf(e)===METRO_MEDIA.length-1},isValue:function(e){return null!=e&&""!==e},isNull:function(e){return null==e},isNegative:function(e){return parseFloat(e)<0},isPositive:function(e){return 0<parseFloat(e)},isZero:function(e){return 0===parseFloat(e.toFixed(2))},between:function(e,t,n,i){return!0===i?t<=e&&e<=n:t<e&&e<n},parseMoney:function(e){return Number(parseFloat(e.replace(/[^0-9-.]/g,"")))},parseCard:function(e){return e.replace(/[^0-9]/g,"")},parsePhone:function(e){return this.parseCard(e)},parseNumber:function(e,t,n){return e.replace(new RegExp("\\"+t,"g"),"").replace(new RegExp("\\"+n,"g"),".")},nearest:function(e,t,n){return e/=t,e=Math[!0===n?"floor":"ceil"](e)*t},bool:function(e){switch(e){case!0:case"true":case 1:case"1":case"on":case"yes":return!0;default:return!1}},copy:function(e){var t,n,i=document.body,s=o(e)[0];if(document.createRange&&window.getSelection){t=document.createRange(),(n=window.getSelection()).removeAllRanges();try{t.selectNodeContents(s),n.addRange(t)}catch(e){t.selectNode(s),n.addRange(t)}}else i.createTextRange&&((t=i.createTextRange()).moveToElementText(s),t.select());document.execCommand("Copy"),window.getSelection?window.getSelection().empty?window.getSelection().empty():window.getSelection().removeAllRanges&&window.getSelection().removeAllRanges():document.selection&&document.selection.empty()},isLocalhost:function(e){return e=e||".local","localhost"===location.hostname||"127.0.0.1"===location.hostname||"[::1]"===location.hostname||""===location.hostname||window.location.hostname.match(/^127(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/)||-1!==location.hostname.indexOf(e)},decCount:function(e){return e%1==0?0:e.toString().split(".")[1].length},randomColor:function(){return"#"+((1<<24)+(o.random(0,255)<<16)+(o.random(0,255)<<8)+o.random(0,255)).toString(16).slice(1)}},!0===window.METRO_GLOBAL_COMMON&&(window.Utils=s.utils)}(Metro,m4q),function(e,a){"use strict";var o={duration:METRO_ANIMATION_DURATION,ease:"linear"};e.animations={switchIn:function(e){a(e).hide().css({left:0,top:0}).show()},switchOut:function(e){a(e).hide()},switch:function(e,t){this.switchOut(e),this.switchIn(t)},slideUpIn:function(e,t){var n,i=a(e),s=i.parent().outerHeight(!0);n=a.extend({},o,t),i.css({top:s,left:0,zIndex:2}).animate({draw:{top:0,opacity:1},dur:n.duration,ease:n.ease})},slideUpOut:function(e,t){var n,i=a(e),s=i.parent().outerHeight(!0);n=a.extend({},o,t),i.css({zIndex:1}).animate({draw:{top:-s,opacity:0},dur:n.duration,ease:n.ease})},slideUp:function(e,t,n){this.slideUpOut(e,n),this.slideUpIn(t,n)},slideDownIn:function(e,t){var n,i=a(e),s=i.parent().outerHeight(!0);n=a.extend({},o,t),i.css({left:0,top:-s,zIndex:2}).animate({draw:{top:0,opacity:1},dur:n.duration,ease:n.ease})},slideDownOut:function(e,t){var n,i=a(e),s=i.parent().outerHeight(!0);n=a.extend({},o,t),i.css({zIndex:1}).animate({draw:{top:s,opacity:0},dur:n.duration,ease:n.ease})},slideDown:function(e,t,n){this.slideDownOut(e,n),this.slideDownIn(t,n)},slideLeftIn:function(e,t){var n,i=a(e),s=i.parent().outerWidth(!0);n=a.extend({},o,t),i.css({left:s,zIndex:2}).animate({draw:{left:0,opacity:1},dur:n.duration,ease:n.ease})},slideLeftOut:function(e,t){var n,i=a(e),s=i.parent().outerWidth(!0);n=a.extend({},o,t),i.css({zIndex:1}).animate({draw:{left:-s,opacity:0},dur:n.duration,ease:n.ease})},slideLeft:function(e,t,n){this.slideLeftOut(e,n),this.slideLeftIn(t,n)},slideRightIn:function(e,t){var n,i=a(e),s=i.parent().outerWidth(!0);n=a.extend({},o,t),i.css({left:-s,zIndex:2}).animate({draw:{left:0,opacity:1},dur:n.duration,ease:n.ease})},slideRightOut:function(e,t){var n,i=a(e),s=i.parent().outerWidth(!0);n=a.extend({},o,t),i.css({zIndex:1}).animate({draw:{left:s,opacity:0},dur:n.duration,ease:n.ease})},slideRight:function(e,t,n){this.slideRightOut(e,n),this.slideRightIn(t,n)},fadeIn:function(e,t){var n=a.extend({},o,t);a(e).css({top:0,left:0,opacity:0}).animate({draw:{opacity:1},dur:n.duration,ease:n.ease})},fadeOut:function(e,t){var n=a.extend({},o,t);a(e).animate({draw:{opacity:0},dur:n.duration,ease:n.ease})},fade:function(e,t,n){this.fadeOut(e,n),this.fadeIn(t,n)},zoomIn:function(e,t){var n=a.extend({},o,t);a(e).css({top:0,left:0,opacity:0,transform:"scale(3)",zIndex:2}).animate({draw:{scale:1,opacity:1},dur:n.duration,ease:n.ease})},zoomOut:function(e,t){var n=a.extend({},o,t);a(e).css({zIndex:1}).animate({draw:{scale:3,opacity:0},dur:n.duration,ease:n.ease})},zoom:function(e,t,n){this.zoomOut(e,n),this.zoomIn(t,n)},swirlIn:function(e,t){var n=a.extend({},o,t);a(e).css({top:0,left:0,opacity:0,transform:"scale(3) rotate(180deg)",zIndex:2}).animate({draw:{scale:1,rotate:0,opacity:1},dur:n.duration,ease:n.ease})},swirlOut:function(e,t){var n=a.extend({},o,t);a(e).css({zIndex:1}).animate({draw:{scale:3,rotate:"180deg",opacity:0},dur:n.duration,ease:n.ease})},swirl:function(e,t,n){this.swirlOut(e,n),this.swirlIn(t,n)}},!0===window.METRO_GLOBAL_COMMON&&(window.Animations=e.animations)}(Metro,m4q),function(e,v){"use strict";var i="hex",t="rgb",p="rgba",n="hsv",s="hsl",f="hsla",a="cmyk",o="unknown";e.colorsSetup=function(e){g=v.extend({},g,e)},window.metroColorsSetup,e.colorsSetup(window.metroColorsSetup);var g={angle:30,algorithm:1,step:.1,distance:5,tint1:.8,tint2:.4,shade1:.6,shade2:.3,alpha:1};function u(e,t,n){this.r=e||0,this.g=t||0,this.b=n||0}function r(e,t,n,i){this.r=e||0,this.g=t||0,this.b=n||0,this.a=i||1}function w(e,t,n){this.h=e||0,this.s=t||0,this.v=n||0}function l(e,t,n){this.h=e||0,this.s=t||0,this.l=n||0}function c(e,t,n,i){this.h=e||0,this.s=t||0,this.l=n||0,this.a=i||1}function d(e,t,n,i){this.c=e||0,this.m=t||0,this.y=n||0,this.k=i||0}u.prototype.toString=function(){return"rgb("+[this.r,this.g,this.b].join(",")+")"},r.prototype.toString=function(){return"rgba("+[this.r,this.g,this.b,this.a].join(",")+")"},w.prototype.toString=function(){return"hsv("+[this.h,this.s,this.v].join(",")+")"},l.prototype.toString=function(){return"hsl("+[this.h,this.s,this.l].join(",")+")"},c.prototype.toString=function(){return"hsla("+[this.h,this.s,this.l,this.a].join(",")+")"},d.prototype.toString=function(){return"cmyk("+[this.c,this.m,this.y,this.k].join(",")+")"};function h(e,t){this._setValue(e),this._setOptions(t)}var m={PALETTES:{ALL:"all",METRO:"metro",STANDARD:"standard"},metro:{lime:"#a4c400",green:"#60a917",emerald:"#008a00",blue:"#00AFF0",teal:"#00aba9",cyan:"#1ba1e2",cobalt:"#0050ef",indigo:"#6a00ff",violet:"#aa00ff",pink:"#dc4fad",magenta:"#d80073",crimson:"#a20025",red:"#CE352C",orange:"#fa6800",amber:"#f0a30a",yellow:"#fff000",brown:"#825a2c",olive:"#6d8764",steel:"#647687",mauve:"#76608a",taupe:"#87794e"},standard:{aliceBlue:"#f0f8ff",antiqueWhite:"#faebd7",aqua:"#00ffff",aquamarine:"#7fffd4",azure:"#f0ffff",beige:"#f5f5dc",bisque:"#ffe4c4",black:"#000000",blanchedAlmond:"#ffebcd",blue:"#0000ff",blueViolet:"#8a2be2",brown:"#a52a2a",burlyWood:"#deb887",cadetBlue:"#5f9ea0",chartreuse:"#7fff00",chocolate:"#d2691e",coral:"#ff7f50",cornflowerBlue:"#6495ed",cornsilk:"#fff8dc",crimson:"#dc143c",cyan:"#00ffff",darkBlue:"#00008b",darkCyan:"#008b8b",darkGoldenRod:"#b8860b",darkGray:"#a9a9a9",darkGreen:"#006400",darkKhaki:"#bdb76b",darkMagenta:"#8b008b",darkOliveGreen:"#556b2f",darkOrange:"#ff8c00",darkOrchid:"#9932cc",darkRed:"#8b0000",darkSalmon:"#e9967a",darkSeaGreen:"#8fbc8f",darkSlateBlue:"#483d8b",darkSlateGray:"#2f4f4f",darkTurquoise:"#00ced1",darkViolet:"#9400d3",deepPink:"#ff1493",deepSkyBlue:"#00bfff",dimGray:"#696969",dodgerBlue:"#1e90ff",fireBrick:"#b22222",floralWhite:"#fffaf0",forestGreen:"#228b22",fuchsia:"#ff00ff",gainsboro:"#DCDCDC",ghostWhite:"#F8F8FF",gold:"#ffd700",goldenRod:"#daa520",gray:"#808080",green:"#008000",greenYellow:"#adff2f",honeyDew:"#f0fff0",hotPink:"#ff69b4",indianRed:"#cd5c5c",indigo:"#4b0082",ivory:"#fffff0",khaki:"#f0e68c",lavender:"#e6e6fa",lavenderBlush:"#fff0f5",lawnGreen:"#7cfc00",lemonChiffon:"#fffacd",lightBlue:"#add8e6",lightCoral:"#f08080",lightCyan:"#e0ffff",lightGoldenRodYellow:"#fafad2",lightGray:"#d3d3d3",lightGreen:"#90ee90",lightPink:"#ffb6c1",lightSalmon:"#ffa07a",lightSeaGreen:"#20b2aa",lightSkyBlue:"#87cefa",lightSlateGray:"#778899",lightSteelBlue:"#b0c4de",lightYellow:"#ffffe0",lime:"#00ff00",limeGreen:"#32dc32",linen:"#faf0e6",magenta:"#ff00ff",maroon:"#800000",mediumAquaMarine:"#66cdaa",mediumBlue:"#0000cd",mediumOrchid:"#ba55d3",mediumPurple:"#9370db",mediumSeaGreen:"#3cb371",mediumSlateBlue:"#7b68ee",mediumSpringGreen:"#00fa9a",mediumTurquoise:"#48d1cc",mediumVioletRed:"#c71585",midnightBlue:"#191970",mintCream:"#f5fffa",mistyRose:"#ffe4e1",moccasin:"#ffe4b5",navajoWhite:"#ffdead",navy:"#000080",oldLace:"#fdd5e6",olive:"#808000",oliveDrab:"#6b8e23",orange:"#ffa500",orangeRed:"#ff4500",orchid:"#da70d6",paleGoldenRod:"#eee8aa",paleGreen:"#98fb98",paleTurquoise:"#afeeee",paleVioletRed:"#db7093",papayaWhip:"#ffefd5",peachPuff:"#ffdab9",peru:"#cd853f",pink:"#ffc0cb",plum:"#dda0dd",powderBlue:"#b0e0e6",purple:"#800080",rebeccaPurple:"#663399",red:"#ff0000",rosyBrown:"#bc8f8f",royalBlue:"#4169e1",saddleBrown:"#8b4513",salmon:"#fa8072",sandyBrown:"#f4a460",seaGreen:"#2e8b57",seaShell:"#fff5ee",sienna:"#a0522d",silver:"#c0c0c0",slyBlue:"#87ceeb",slateBlue:"#6a5acd",slateGray:"#708090",snow:"#fffafa",springGreen:"#00ff7f",steelBlue:"#4682b4",tan:"#d2b48c",teal:"#008080",thistle:"#d8bfd8",tomato:"#ff6347",turquoise:"#40e0d0",violet:"#ee82ee",wheat:"#f5deb3",white:"#ffffff",whiteSmoke:"#f5f5f5",yellow:"#ffff00",yellowGreen:"#9acd32"},all:{},init:function(){return this.all=v.extend({},this.standard,this.metro),this},color:function(e,t){return void 0!==this[t=t||this.PALETTES.ALL][e]&&this[t][e]},palette:function(e){return e=e||this.PALETTES.ALL,Object.keys(this[e])},expandHexColor:function(e){if("string"!=typeof e)throw new Error("Value is not a string!");if("#"!==e[0]||4!==e.length)return"#"===e[0]?e:"#"+e;return"#"+e.replace(/^#?([a-f\d])([a-f\d])([a-f\d])$/i,function(e,t,n,i){return t+t+n+n+i+i})},colors:function(e){return e=e||this.PALETTES.ALL,Object.values(this[e])},random:function(e,t){var n;return e=e||i,t=void 0!==t?t:1,n="#"+((1<<24)+(v.random(0,255)<<16)+(v.random(0,255)<<8)+v.random(0,255)).toString(16).slice(1),"hex"===e?n:this.toColor(n,e,t)},parse:function(e){var t=e.toLowerCase(),n=t.replace(/[^\d.,]/g,"").split(",").map(function(e){return t.includes("hs")?parseFloat(e):parseInt(e)});return"#"===t[0]?this.expandHexColor(t):t.includes("rgba")?new r(n[0],n[1],n[2],n[3]):t.includes("rgb")?new u(n[0],n[1],n[2]):t.includes("cmyk")?new d(n[0],n[1],n[2],n[3]):t.includes("hsv")?new w(n[0],n[1],n[2]):t.includes("hsla")?new c(n[0],n[1],n[2],n[3]):t.includes("hsl")?new l(n[0],n[1],n[2]):t},createColor:function(e,t){var n;return e=e||"hex","string"==typeof(t=t||"#000000")&&(n=this.parse(t)),this.isColor(n)||(n="#000000"),this.toColor(n,e.toLowerCase())},isDark:function(e){if(this.isColor(e)){var t=this.toRGB(e);return(299*t.r+587*t.g+114*t.b)/1e3<128}},isLight:function(e){return!this.isDark(e)},isHSV:function(e){return e instanceof w},isHSL:function(e){return e instanceof l},isHSLA:function(e){return e instanceof c},isRGB:function(e){return e instanceof u},isRGBA:function(e){return e instanceof r},isCMYK:function(e){return e instanceof d},isHEX:function(e){return/(^#[0-9A-F]{6}$)|(^#[0-9A-F]{3}$)/i.test(e)},isColor:function(e){return!!e&&(this.isHEX(e)||this.isRGB(e)||this.isRGBA(e)||this.isHSV(e)||this.isHSL(e)||this.isHSLA(e)||this.isCMYK(e))},check:function(e,t){if(!this["is"+t.toUpperCase()](e))throw new Error("Value is not a "+t+" color type!")},colorType:function(e){return this.isHEX(e)?i:this.isRGB(e)?t:this.isRGBA(e)?p:this.isHSV(e)?n:this.isHSL(e)?s:this.isHSLA(e)?f:this.isCMYK(e)?a:o},equal:function(e,t){return!(!this.isColor(e)||!this.isColor(t))&&this.toHEX(e)===this.toHEX(t)},colorToString:function(e){return e.toString()},hex2rgb:function(e){if("string"!=typeof e)throw new Error("Value is not a string!");var t=/^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(this.expandHexColor(e)),n=[parseInt(t[1],16),parseInt(t[2],16),parseInt(t[3],16)];return t?new u(n[0],n[1],n[2]):null},rgb2hex:function(e){return this.check(e,"rgb"),"#"+((1<<24)+(e.r<<16)+(e.g<<8)+e.b).toString(16).slice(1)},rgb2hsv:function(e){this.check(e,"rgb");var t,n,i,s=new w,a=e.r/255,o=e.g/255,r=e.b/255,l=Math.max(a,o,r),c=Math.min(a,o,r),d=l-c;return n=0===(i=l)?0:1-c/l,t=l===c?0:l===a&&r<=o?(o-r)/d*60:l===a&&o<r?(o-r)/d*60+360:l===o?(r-a)/d*60+120:l===r?(a-o)/d*60+240:0,s.h=t,s.s=n,s.v=i,s},hsv2rgb:function(e){var t,n,i;this.check(e,"hsv");var s=e.h,a=100*e.s,o=100*e.v,r=(100-a)*o/100,l=s%60/60*(o-r),c=r+l,d=o-l;switch(Math.floor(s/60)){case 0:t=o,n=c,i=r;break;case 1:t=d,n=o,i=r;break;case 2:t=r,n=o,i=c;break;case 3:t=r,n=d,i=o;break;case 4:t=c,n=r,i=o;break;case 5:t=o,n=r,i=d}return new u(Math.round(255*t/100),Math.round(255*n/100),Math.round(255*i/100))},hsv2hex:function(e){return this.check(e,"hsv"),this.rgb2hex(this.hsv2rgb(e))},hex2hsv:function(e){return this.check(e,"hex"),this.rgb2hsv(this.hex2rgb(e))},rgb2cmyk:function(e){this.check(e,"rgb");var t=new d,n=e.r/255,i=e.g/255,s=e.b/255;return t.k=Math.min(1-n,1-i,1-s),t.c=1-t.k==0?0:(1-n-t.k)/(1-t.k),t.m=1-t.k==0?0:(1-i-t.k)/(1-t.k),t.y=1-t.k==0?0:(1-s-t.k)/(1-t.k),t.c=Math.round(100*t.c),t.m=Math.round(100*t.m),t.y=Math.round(100*t.y),t.k=Math.round(100*t.k),t},cmyk2rgb:function(e){return this.check(e,"cmyk"),new u(Math.floor(255*(1-e.c/100)*(1-e.k/100)),Math.ceil(255*(1-e.m/100)*(1-e.k/100)),Math.ceil(255*(1-e.y/100)*(1-e.k/100)))},hsv2hsl:function(e){var t,n,i,s;return this.check(e,"hsv"),t=e.h,i=(2-e.s)*e.v,n=e.s*e.v,0===i?n=0:0===(s=i<=1?i:2-i)?n=0:n/=s,new l(t,n,i/=2)},hsl2hsv:function(e){var t,n,i,s;return this.check(e,"hsl"),t=e.h,i=((s=2*e.l)+(n=e.s*(s<=1?s:2-s)))/2,new w(t,n=s+n===0?0:2*n/(s+n),i)},rgb2websafe:function(e){return this.check(e,"rgb"),new u(51*Math.round(e.r/51),51*Math.round(e.g/51),51*Math.round(e.b/51))},rgba2websafe:function(e){this.check(e,"rgba");var t=this.rgb2websafe(e);return new r(t.r,t.g,t.b,e.a)},hex2websafe:function(e){return this.check(e,"hex"),this.rgb2hex(this.rgb2websafe(this.hex2rgb(e)))},hsv2websafe:function(e){return this.check(e,"hsv"),this.rgb2hsv(this.rgb2websafe(this.toRGB(e)))},hsl2websafe:function(e){return this.check(e,"hsl"),this.hsv2hsl(this.rgb2hsv(this.rgb2websafe(this.toRGB(e))))},cmyk2websafe:function(e){return this.check(e,"cmyk"),this.rgb2cmyk(this.rgb2websafe(this.cmyk2rgb(e)))},websafe:function(e){return this.isHEX(e)?this.hex2websafe(e):this.isRGB(e)?this.rgb2websafe(e):this.isRGBA(e)?this.rgba2websafe(e):this.isHSV(e)?this.hsv2websafe(e):this.isHSL(e)?this.hsl2websafe(e):this.isCMYK(e)?this.cmyk2websafe(e):e},toColor:function(e,t,n){var i;switch(t.toLowerCase()){case"hex":i=this.toHEX(e);break;case"rgb":i=this.toRGB(e);break;case"rgba":i=this.toRGBA(e,n);break;case"hsl":i=this.toHSL(e);break;case"hsla":i=this.toHSLA(e,n);break;case"hsv":i=this.toHSV(e);break;case"cmyk":i=this.toCMYK(e);break;default:i=e}return i},toHEX:function(e){return"string"==typeof e?this.expandHexColor(e):this.rgb2hex(this.toRGB(e))},toRGB:function(e){if(this.isRGB(e))return e;if(this.isRGBA(e))return new u(e.r,e.g,e.b);if(this.isHSV(e))return this.hsv2rgb(e);if(this.isHSL(e))return this.hsv2rgb(this.hsl2hsv(e));if(this.isHSLA(e))return this.hsv2rgb(this.hsl2hsv(e));if(this.isHEX(e))return this.hex2rgb(e);if(this.isCMYK(e))return this.cmyk2rgb(e);throw new Error("Unknown color format!")},toRGBA:function(e,t){if(this.isRGBA(e))return t&&(e.a=t),e;var n=this.toRGB(e);return new r(n.r,n.g,n.b,t)},toHSV:function(e){return this.rgb2hsv(this.toRGB(e))},toHSL:function(e){return this.hsv2hsl(this.rgb2hsv(this.toRGB(e)))},toHSLA:function(e,t){if(this.isHSLA(e))return t&&(e.a=t),e;var n=this.hsv2hsl(this.rgb2hsv(this.toRGB(e)));return n.a=t,new c(n.h,n.s,n.l,n.a)},toCMYK:function(e){return this.rgb2cmyk(this.toRGB(e))},grayscale:function(e){var t=this.toRGB(e),n=this.colorType(e).toLowerCase(),i=Math.round(.2125*t.r+.7154*t.g+.0721*t.b),s=new u(i,i,i);return this.toColor(s,n)},darken:function(e,t){return t=void 0!==t?t:10,this.lighten(e,-1*Math.abs(t))},lighten:function(e,t){var n,i,s,a,o,r,l,c,d,u,h;for(isNaN(t)&&(t=10),a=0<t,(n=this.colorType(e).toLowerCase())!==p&&n!==f||(s=e.a);o=this.toHEX(e),r=t,d=c=l=void 0,u=o.slice(1),h=parseInt(u,16),255<(l=(h>>16)+r)?l=255:l<0&&(l=0),255<(d=(h>>8&255)+r)?d=255:d<0&&(d=0),255<(c=(255&h)+r)?c=255:c<0&&(c=0),a?t--:t++,(i="#"+(c|d<<8|l<<16).toString(16)).length<7;);return this.toColor(i,n,s)},hueShift:function(e,t){var n,i=this.toHSV(e),s=this.colorType(e).toLowerCase(),a=i.h;for(a+=t;360<=a;)a-=360;for(;a<0;)a+=360;return i.h=a,s!==p&&s!==f||(n=e.a),this.toColor(i,s,n)},createScheme:function(e,t,n,i){var s,a,o,r,l,c,d=v.extend({},g,i),u=[],h=this;if(r=(a=this.toHSV(e)).h,l=a.s,c=a.v,!1===this.isHSV(a))return console.warn("The value is a not supported color format!"),!1;function p(e,t,n){return Math.max(t,Math.min(e,n))}function f(e,t,n){return e<t?t:n<e?n:e}function m(e,t){for(e+=t;360<=e;)e-=360;for(;e<0;)e+=360;return e}switch(t){case"monochromatic":case"mono":if(1===d.algorithm)(o=this.hsv2rgb(a)).r=f(Math.round(o.r+(255-o.r)*d.tint1),0,255),o.g=f(Math.round(o.g+(255-o.g)*d.tint1),0,255),o.b=f(Math.round(o.b+(255-o.b)*d.tint1),0,255),u.push(this.rgb2hsv(o)),(o=this.hsv2rgb(a)).r=f(Math.round(o.r+(255-o.r)*d.tint2),0,255),o.g=f(Math.round(o.g+(255-o.g)*d.tint2),0,255),o.b=f(Math.round(o.b+(255-o.b)*d.tint2),0,255),u.push(this.rgb2hsv(o)),u.push(a),(o=this.hsv2rgb(a)).r=f(Math.round(o.r*d.shade1),0,255),o.g=f(Math.round(o.g*d.shade1),0,255),o.b=f(Math.round(o.b*d.shade1),0,255),u.push(this.rgb2hsv(o)),(o=this.hsv2rgb(a)).r=f(Math.round(o.r*d.shade2),0,255),o.g=f(Math.round(o.g*d.shade2),0,255),o.b=f(Math.round(o.b*d.shade2),0,255),u.push(this.rgb2hsv(o));else if(2===d.algorithm)for(u.push(a),s=1;s<=d.distance;s++)c=p(c-d.step,0,1),l=p(l-d.step,0,1),u.push(new w(r,l,c));else if(3===d.algorithm)for(u.push(a),s=1;s<=d.distance;s++)c=p(c-d.step,0,1),u.push(new w(r,l,c));else c=p(a.v+2*d.step,0,1),u.push(new w(r,l,c)),c=p(a.v+d.step,0,1),u.push(new w(r,l,c)),u.push(a),l=a.s,c=a.v,c=p(a.v-d.step,0,1),u.push(new w(r,l,c)),c=p(a.v-2*d.step,0,1),u.push(new w(r,l,c));break;case"complementary":case"complement":case"comp":u.push(a),r=m(a.h,180),u.push(new w(r,l,c));break;case"double-complementary":case"double-complement":case"double":u.push(a),r=m(r,180),u.push(new w(r,l,c)),r=m(r,d.angle),u.push(new w(r,l,c)),r=m(r,180),u.push(new w(r,l,c));break;case"analogous":case"analog":r=m(r,d.angle),u.push(new w(r,l,c)),u.push(a),r=m(a.h,0-d.angle),u.push(new w(r,l,c));break;case"triadic":case"triad":for(u.push(a),s=1;s<3;s++)r=m(r,120),u.push(new w(r,l,c));break;case"tetradic":case"tetra":u.push(a),r=m(a.h,180),u.push(new w(r,l,c)),r=m(a.h,-1*d.angle),u.push(new w(r,l,c)),r=m(r,180),u.push(new w(r,l,c));break;case"square":for(u.push(a),s=1;s<4;s++)r=m(r,90),u.push(new w(r,l,c));break;case"split-complementary":case"split-complement":case"split":r=m(r,180-d.angle),u.push(new w(r,l,c)),u.push(a),r=m(a.h,180+d.angle),u.push(new w(r,l,c));break;default:console.warn("Unknown scheme name")}return function(e,t){var n;switch(t){case"hex":n=e.map(function(e){return h.toHEX(e)});break;case"rgb":n=e.map(function(e){return h.toRGB(e)});break;case"rgba":n=e.map(function(e){return h.toRGBA(e,d.alpha)});break;case"hsl":n=e.map(function(e){return h.toHSL(e)});break;case"hsla":n=e.map(function(e){return h.toHSLA(e,d.alpha)});break;case"cmyk":n=e.map(function(e){return h.toCMYK(e)});break;default:n=e}return n}(u,n)},getScheme:function(){return this.createScheme.apply(this,arguments)}};h.prototype={_setValue:function(e){"string"==typeof e&&(e=m.expandHexColor(m.parse(e))),m.isColor(e)||(e="#000000"),this._value=e},_setOptions:function(e){e="object"==typeof e?e:{},this._options=v.extend({},g,e)},getOptions:function(){return this._options},setOptions:function(e){this._setOptions(e)},setValue:function(e){this._setValue(e)},getValue:function(){return this._value},toRGB:function(){if(this._value)return this._value=m.toRGB(this._value),this},rgb:function(){return this._value?m.toRGB(this._value):void 0},toRGBA:function(e){if(this._value)return m.isRGBA(this._value)?e&&(this._value=m.toRGBA(this._value,e)):this._value=m.toRGBA(this._value,e),this},rgba:function(e){return this._value?m.isRGBA(this._value)?this._value:m.toRGBA(this._value,e):void 0},toHEX:function(){if(this._value)return this._value=m.toHEX(this._value),this},hex:function(){return this._value?m.toHEX(this._value):void 0},toHSV:function(){if(this._value)return this._value=m.toHSV(this._value),this},hsv:function(){return this._value?m.toHSV(this._value):void 0},toHSL:function(){if(this._value)return this._value=m.toHSL(this._value),this},hsl:function(){return this._value?m.toHSL(this._value):void 0},toHSLA:function(e){if(this._value)return m.isHSLA(this._value)?e&&(this._value=m.toHSLA(this._value,e)):this._value=m.toHSLA(this._value,e),this},hsla:function(e){return this._value?m.isHSLA(this._value)?this._value:m.toHSLA(this._value,e):void 0},toCMYK:function(){if(this._value)return this._value=m.toCMYK(this._value),this},cmyk:function(){return this._value?m.toCMYK(this._value):void 0},toWebsafe:function(){if(this._value)return this._value=m.websafe(this._value),this},websafe:function(){return this._value?m.websafe(this._value):void 0},toString:function(){return this._value?m.colorToString(this._value):void 0},darken:function(e){if(e=e||10,this._value)return this._value=m.darken(this._value,e),this},lighten:function(e){if(e=e||10,this._value)return this._value=m.lighten(this._value,e),this},isDark:function(){return this._value?m.isDark(this._value):void 0},isLight:function(){return this._value?m.isLight(this._value):void 0},hueShift:function(e){if(this._value)return this._value=m.hueShift(this._value,e),this},grayscale:function(){if(this._value&&this.type!==o)return this._value=m.grayscale(this._value,(""+this.type).toLowerCase()),this},type:function(){return m.colorType(this._value)},createScheme:function(e,t,n){return this._value?m.createScheme(this._value,e,t,n):void 0},getScheme:function(){return this.createScheme.apply(this,arguments)},equal:function(e){return m.equal(this._value,e)}},e.colors=m.init(),window.Color=e.Color=h,!0===window.METRO_GLOBAL_COMMON&&(window.Colors=e.colors)}(Metro,m4q),function(e,u){"use strict";var h=e.utils,t={init:function(){return this},options:{csvDelimiter:"\t",csvNewLine:"\r\n",includeHeader:!0},setup:function(e){return this.options=u.extend({},this.options,e),this},base64:function(e){return window.btoa(unescape(encodeURIComponent(e)))},b64toBlob:function(e,t,n){t=t||"",n=n||512;var i,s=window.atob(e),a=[];for(i=0;i<s.length;i+=n){var o,r=s.slice(i,i+n),l=new Array(r.length);for(o=0;o<r.length;o+=1)l[o]=r.charCodeAt(o);var c=new window.Uint8Array(l);a.push(c)}return new Blob(a,{type:t})},tableToCSV:function(e,t,n){var i,s,a,o,r,l,c=this.options,d="";if(c=u.extend({},c,n),e=u(e)[0],h.bool(c.includeHeader))for(s=e.querySelectorAll("thead")[0],a=0;a<s.rows.length;a++){for(r=s.rows[a],o=0;o<r.cells.length;o++)l=r.cells[o],d+=(o?c.csvDelimiter:"")+l.textContent.trim();d+=c.csvNewLine}for(i=e.querySelectorAll("tbody")[0],a=0;a<i.rows.length;a++){for(r=i.rows[a],o=0;o<r.cells.length;o++)l=r.cells[o],d+=(o?c.csvDelimiter:"")+l.textContent.trim();d+=c.csvNewLine}return h.isValue(t)?this.createDownload(this.base64("\ufeff"+d),"application/csv",t):d},createDownload:function(e,t,n){var i,s,a;return(s=document.createElement("a")).style.display="none",document.body.appendChild(s),i=this.b64toBlob(e,t),a=window.URL.createObjectURL(i),s.href=a,s.download=n||h.elementId("download"),s.click(),window.URL.revokeObjectURL(a),document.body.removeChild(s),!0}};e.export=t.init(),!0===window.METRO_GLOBAL_COMMON&&(window.Export=e.export)}(Metro,m4q),function(e){"use strict";e.md5=function(e){function r(e,t){return e<<t|e>>>32-t}function l(e,t){var n,i,s,a,o;return s=2147483648&e,a=2147483648&t,o=(1073741823&e)+(1073741823&t),(n=1073741824&e)&(i=1073741824&t)?2147483648^o^s^a:n|i?1073741824&o?3221225472^o^s^a:1073741824^o^s^a:o^s^a}function t(e,t,n,i,s,a,o){return l(r(e=l(e,l(l(function(e,t,n){return e&t|~e&n}(t,n,i),s),o)),a),t)}function n(e,t,n,i,s,a,o){return l(r(e=l(e,l(l(function(e,t,n){return e&n|t&~n}(t,n,i),s),o)),a),t)}function i(e,t,n,i,s,a,o){return l(r(e=l(e,l(l(function(e,t,n){return e^t^n}(t,n,i),s),o)),a),t)}function s(e,t,n,i,s,a,o){return l(r(e=l(e,l(l(function(e,t,n){return t^(e|~n)}(t,n,i),s),o)),a),t)}function a(e){var t,n="",i="";for(t=0;t<=3;t++)n+=(i="0"+(e>>>8*t&255).toString(16)).substr(i.length-2,2);return n}var o,c,d,u,h,p,f,m,v,g;for(o=function(e){for(var t,n=e.length,i=n+8,s=16*(1+(i-i%64)/64),a=Array(s-1),o=0,r=0;r<n;)o=r%4*8,a[t=(r-r%4)/4]=a[t]|e.charCodeAt(r)<<o,r++;return o=r%4*8,a[t=(r-r%4)/4]=a[t]|128<<o,a[s-2]=n<<3,a[s-1]=n>>>29,a}(e=function(e){e=e.replace(/\r\n/g,"\n");for(var t="",n=0;n<e.length;n++){var i=e.charCodeAt(n);i<128?t+=String.fromCharCode(i):(127<i&&i<2048?t+=String.fromCharCode(i>>6|192):(t+=String.fromCharCode(i>>12|224),t+=String.fromCharCode(i>>6&63|128)),t+=String.fromCharCode(63&i|128))}return t}(e)),f=1732584193,m=4023233417,v=2562383102,g=271733878,c=0;c<o.length;c+=16)m=s(m=s(m=s(m=s(m=i(m=i(m=i(m=i(m=n(m=n(m=n(m=n(m=t(m=t(m=t(m=t(u=m,v=t(h=v,g=t(p=g,f=t(d=f,m,v,g,o[c],7,3614090360),m,v,o[c+1],12,3905402710),f,m,o[c+2],17,606105819),g,f,o[c+3],22,3250441966),v=t(v,g=t(g,f=t(f,m,v,g,o[c+4],7,4118548399),m,v,o[c+5],12,1200080426),f,m,o[c+6],17,2821735955),g,f,o[c+7],22,4249261313),v=t(v,g=t(g,f=t(f,m,v,g,o[c+8],7,1770035416),m,v,o[c+9],12,2336552879),f,m,o[c+10],17,4294925233),g,f,o[c+11],22,2304563134),v=t(v,g=t(g,f=t(f,m,v,g,o[c+12],7,1804603682),m,v,o[c+13],12,4254626195),f,m,o[c+14],17,2792965006),g,f,o[c+15],22,1236535329),v=n(v,g=n(g,f=n(f,m,v,g,o[c+1],5,4129170786),m,v,o[c+6],9,3225465664),f,m,o[c+11],14,643717713),g,f,o[c],20,3921069994),v=n(v,g=n(g,f=n(f,m,v,g,o[c+5],5,3593408605),m,v,o[c+10],9,38016083),f,m,o[c+15],14,3634488961),g,f,o[c+4],20,3889429448),v=n(v,g=n(g,f=n(f,m,v,g,o[c+9],5,568446438),m,v,o[c+14],9,3275163606),f,m,o[c+3],14,4107603335),g,f,o[c+8],20,1163531501),v=n(v,g=n(g,f=n(f,m,v,g,o[c+13],5,2850285829),m,v,o[c+2],9,4243563512),f,m,o[c+7],14,1735328473),g,f,o[c+12],20,2368359562),v=i(v,g=i(g,f=i(f,m,v,g,o[c+5],4,4294588738),m,v,o[c+8],11,2272392833),f,m,o[c+11],16,1839030562),g,f,o[c+14],23,4259657740),v=i(v,g=i(g,f=i(f,m,v,g,o[c+1],4,2763975236),m,v,o[c+4],11,1272893353),f,m,o[c+7],16,4139469664),g,f,o[c+10],23,3200236656),v=i(v,g=i(g,f=i(f,m,v,g,o[c+13],4,681279174),m,v,o[c],11,3936430074),f,m,o[c+3],16,3572445317),g,f,o[c+6],23,76029189),v=i(v,g=i(g,f=i(f,m,v,g,o[c+9],4,3654602809),m,v,o[c+12],11,3873151461),f,m,o[c+15],16,530742520),g,f,o[c+2],23,3299628645),v=s(v,g=s(g,f=s(f,m,v,g,o[c],6,4096336452),m,v,o[c+7],10,1126891415),f,m,o[c+14],15,2878612391),g,f,o[c+5],21,4237533241),v=s(v,g=s(g,f=s(f,m,v,g,o[c+12],6,1700485571),m,v,o[c+3],10,2399980690),f,m,o[c+10],15,4293915773),g,f,o[c+1],21,2240044497),v=s(v,g=s(g,f=s(f,m,v,g,o[c+8],6,1873313359),m,v,o[c+15],10,4264355552),f,m,o[c+6],15,2734768916),g,f,o[c+13],21,1309151649),v=s(v,g=s(g,f=s(f,m,v,g,o[c+4],6,4149444226),m,v,o[c+11],10,3174756917),f,m,o[c+2],15,718787259),g,f,o[c+9],21,3951481745),f=l(f,d),m=l(m,u),v=l(v,h),g=l(g,p);return(a(f)+a(m)+a(v)+a(g)).toLowerCase()},!0===window.METRO_GLOBAL_COMMON&&(window.md5=e.md5)}(Metro,m4q),function(t,o){"use strict";var s=t.utils,n={accordionDeferred:0,showMarker:!0,material:!1,duration:METRO_ANIMATION_DURATION,oneFrame:!0,showActive:!0,activeFrameClass:"",activeHeadingClass:"",activeContentClass:"",onFrameOpen:t.noop,onFrameBeforeOpen:t.noop_true,onFrameClose:t.noop,onFrameBeforeClose:t.noop_true,onAccordionCreate:t.noop};t.accordionSetup=function(e){n=o.extend({},n,e)},window.metroAccordionSetup,t.accordionSetup(window.metroAccordionSetup),t.Component("accordion",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("accordionCreate",{element:e})},_createStructure:function(){var e,t=this,n=this.element,i=this.options,s=n.children(".frame"),a=n.children(".frame.active");n.addClass("accordion"),!0===i.showMarker&&n.addClass("marker-on"),!0===i.material&&n.addClass("material"),e=0===a.length?s[0]:a[0],this._hideAll(),!0===i.showActive&&(!0===i.oneFrame?this._openFrame(e):o.each(a,function(){t._openFrame(this)}))},_createEvents:function(){var n=this,i=this.element,s=this.options,a=i.children(".frame.active");i.on(t.events.click,".heading",function(){var e=o(this),t=e.parent();if(e.closest(".accordion")[0]!==i[0])return!1;t.hasClass("active")?1===a.length&&s.oneFrame||n._closeFrame(t):n._openFrame(t)})},_openFrame:function(e){var t=this.element,n=this.options,i=o(e);if(!1===s.exec(n.onFrameBeforeOpen,[i[0]],t[0]))return!1;!0===n.oneFrame&&this._closeAll(i[0]),i.addClass("active "+n.activeFrameClass),i.children(".heading").addClass(n.activeHeadingClass),i.children(".content").addClass(n.activeContentClass).slideDown(n.duration),this._fireEvent("frameOpen",{frame:i[0]})},_closeFrame:function(e){var t=this.element,n=this.options,i=o(e);i.hasClass("active")&&!1!==s.exec(n.onFrameBeforeClose,[i[0]],t[0])&&(i.removeClass("active "+n.activeFrameClass),i.children(".heading").removeClass(n.activeHeadingClass),i.children(".content").removeClass(n.activeContentClass).slideUp(n.duration),this._fireEvent("frameClose",{frame:i[0]}))},_closeAll:function(e){var t=this,n=this.element.children(".frame");o.each(n,function(){e!==this&&t._closeFrame(this)})},_hideAll:function(){var e=this.element.children(".frame");o.each(e,function(){o(this).children(".content").hide()})},_openAll:function(){var e=this,t=this.element.children(".frame");o.each(t,function(){e._openFrame(this)})},changeAttribute:function(e){},destroy:function(){var e=this.element;return e.off(t.events.click,".heading"),e}})}(Metro,m4q),function(s,a){"use strict";var n={activityDeferred:0,type:"ring",style:"light",size:64,radius:20,onActivityCreate:s.noop};s.activitySetup=function(e){n=a.extend({},n,e)},window.metroActivitySetup,s.activitySetup(window.metroActivitySetup),s.Component("activity",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e,t,n=this.element,i=this.options;switch(n.html("").addClass(i.style+"-style").addClass("activity-"+i.type),i.type){case"metro":!function(){for(e=0;e<5;e++)a("<div/>").addClass("circle").appendTo(n)}();break;case"square":!function(){for(e=0;e<4;e++)a("<div/>").addClass("square").appendTo(n)}();break;case"cycle":a("<div/>").addClass("cycle").appendTo(n);break;case"simple":a('<svg class="circular"><circle class="path" cx="'+i.size/2+'" cy="'+i.size/2+'" r="'+i.radius+'" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg>').appendTo(n);break;default:!function(){for(e=0;e<5;e++)t=a("<div/>").addClass("wrap").appendTo(n),a("<div/>").addClass("circle").appendTo(t)}()}this._fireEvent("activity-create",{element:n})},changeAttribute:function(e){},destroy:function(){return this.element}}),s.activity={open:function(e){var t=e||{},n='<div data-role="activity" data-type="'+(t.type?t.type:"cycle")+'" data-style="'+(t.style?t.style:"color")+'"></div>',i=t.text?'<div class="text-center">'+t.text+"</div>":"";return s.dialog.create({content:n+i,defaultAction:!1,clsContent:"d-flex flex-column flex-justify-center flex-align-center bg-transparent no-shadow w-auto",clsDialog:"no-border no-shadow bg-transparent global-dialog",autoHide:t.autoHide?t.autoHide:0,overlayClickClose:!0===t.overlayClickClose,overlayColor:t.overlayColor?t.overlayColor:"#000000",overlayAlpha:t.overlayAlpha?t.overlayAlpha:.5,clsOverlay:"global-overlay"})},close:function(e){s.dialog.close(e)}}}(Metro,m4q),function(e,r){"use strict";var l=e.utils,t={adblockDeferred:0,checkInterval:1e3,fireOnce:!0,checkStop:10,onAlert:e.noop,onFishingStart:e.noop,onFishingDone:e.noop};e.adblockSetup=function(e){t=r.extend({},t,e)},window.metroAdblockSetup,e.adblockSetup(window.metroAdblockSetup);var c={bite:function(){r("<div>").addClass("adblock-bite adsense google-adsense dblclick advert topad top_ads topAds textads sponsoredtextlink_container show_ads right-banner rekl mpu module-ad mid_ad mediaget horizontal_ad headerAd contentAd brand-link bottombanner bottom_ad_block block_ad bannertop banner-right banner-body b-banner b-article-aside__banner b-advert adwrapper adverts advertisment advertisement:not(body) advertise advert_list adtable adsense adpic adlist adleft adinfo adi adholder adframe addiv ad_text ad_space ad_right ad_links ad_body ad_block ad_Right adTitle adText".split(" ").shuffle().join(" ")).css({position:"fixed",height:1,width:1,overflow:"hidden",visibility:"visible",top:0,left:0}).append(r("<a href='https://dblclick.net'>").html("dblclick.net")).appendTo("body"),c.options.adblockDeferred?setTimeout(function(){c.fishing()},c.options.adblockDeferred):this.fishing()},fishing:function(){function e(){function e(){clearInterval(o),l.exec(i.onFishingDone),r(window).fire("fishing-done"),t.remove()}var t=r(".adsense.google-adsense.dblclick.advert.adblock-bite"),n=t.find("a");!t.length||!n.length||-1<t.css("display").indexOf("none")||-1<n.css("display").indexOf("none")?(l.exec(c.options.onAlert),r(window).fire("adblock-alert"),!0===c.options.fireOnce?e():0===--s&&e()):!1!==a&&0===--a&&e()}var i=c.options,s="number"==typeof i.fireOnce?i.fireOnce:0,a=i.checkStop,o=!1;l.exec(i.onFishingStart),r(window).fire("fishing-start"),o=setInterval(function(){e()},c.options.checkInterval),e()}};e.Adblock=c,r(function(){c.options=r.extend({},t),r(window).on("metro-initiated",function(){c.bite()})})}(Metro,m4q),function(a,o){"use strict";var r=a.colors,l=a.utils,n={appbarDeferred:0,expand:!1,expandPoint:null,duration:100,onMenuOpen:a.noop,onMenuClose:a.noop,onMenuCollapse:a.noop,onMenuExpand:a.noop,onAppBarCreate:a.noop};a.appBarSetup=function(e){n=o.extend({},n,e)},window.metroAppBarSetup,a.appBarSetup(window.metroAppBarSetup),a.Component("app-bar",{init:function(e,t){return this._super(t,e,n,{id:l.elementId("app-bar")}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("app-bar-create",{element:e})},_createStructure:function(){var e,t,n=this.element,i=this.options;if(n.addClass("app-bar"),0===(e=n.find(".hamburger")).length){e=o("<button>").attr("type","button").addClass("hamburger menu-down");for(var s=0;s<3;s++)o("<span>").addClass("line").appendTo(e);!0===r.isLight(l.computedRgbToHex(l.getStyleOne(n,"background-color")))&&e.addClass("dark")}n.prepend(e),0===(t=n.find(".app-bar-menu")).length?e.css("display","none"):l.addCssRule(a.sheet,".app-bar-menu li","list-style: none!important;"),"block"===e.css("display")?(t.hide().addClass("collapsed"),e.removeClass("hidden")):e.addClass("hidden"),!0===i.expand?(n.addClass("app-bar-expand"),e.addClass("hidden")):l.isValue(i.expandPoint)&&l.mediaExist(i.expandPoint)&&(n.addClass("app-bar-expand"),e.addClass("hidden"))},_createEvents:function(){var e=this,t=this.element,n=this.options,i=t.find(".app-bar-menu"),s=t.find(".hamburger");t.on(a.events.click,".hamburger",function(){0!==i.length&&(i.hasClass("collapsed")?e.open():e.close())}),o(window).on(a.events.resize,function(){!0!==n.expand&&(l.isValue(n.expandPoint)&&l.mediaExist(n.expandPoint)?(t.addClass("app-bar-expand"),l.exec(n.onMenuExpand,null,t[0]),t.fire("menuexpand")):(t.removeClass("app-bar-expand"),l.exec(n.onMenuCollapse,null,t[0]),t.fire("menucollapse"))),0!==i.length&&("block"!==s.css("display")?(i.show(function(){o(this).removeStyleProperty("display")}),s.addClass("hidden")):(s.removeClass("hidden"),s.hasClass("active")?i.show().removeClass("collapsed"):i.hide().addClass("collapsed")))},{ns:this.id})},close:function(){var e=this.element,t=this.options,n=e.find(".app-bar-menu"),i=e.find(".hamburger");n.slideUp(t.duration,function(){n.addClass("collapsed").removeClass("opened"),i.removeClass("active")}),l.exec(t.onMenuClose,[n[0]],e[0]),e.fire("menuclose",{menu:n[0]})},open:function(){var e=this.element,t=this.options,n=e.find(".app-bar-menu"),i=e.find(".hamburger");n.slideDown(t.duration,function(){n.removeClass("collapsed").addClass("opened"),i.addClass("active")}),l.exec(t.onMenuOpen,[n[0]],e[0]),e.fire("menuopen",{menu:n[0]})},changeAttribute:function(e){},destroy:function(){var e=this.element;return e.off(a.events.click,".hamburger"),o(window).off(a.events.resize,{ns:this.id}),e}})}(Metro,m4q),function(s,t){"use strict";var a=s.utils,n={audioVolume:.5,audioSrc:"",onAudioStart:s.noop,onAudioEnd:s.noop,onAudioButtonCreate:s.noop};s.audioButtonSetup=function(e){n=t.extend({},n,e)},window.metroAudioButtonSetup,s.audioButtonSetup(window.metroAudioButtonSetup),s.Component("audio-button",{init:function(e,t){return this._super(t,e,n,{audio:null,canPlay:null,id:a.elementId("audioButton")}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("audioButtonCreate",{element:e})},_createStructure:function(){var e=this.options;this.audio=new Audio(e.audioSrc),this.audio.volume=e.audioVolume},_createEvents:function(){var e=this,t=this.element,n=this.options,i=this.audio;i.addEventListener("loadeddata",function(){e.canPlay=!0}),i.addEventListener("ended",function(){e._fireEvent("audioEnd",{src:n.audioSrc,audio:i})}),t.on(s.events.click,function(){e.play()},{ns:this.id})},play:function(e){var t=this.element,n=this.options,i=this.audio;""!==n.audioSrc&&this.audio.duration&&this.canPlay&&(this._fireEvent("audioStart",{src:n.audioSrc,audio:i}),i.pause(),i.currentTime=0,i.play(),a.exec(e,[i],t[0]))},stop:function(e){var t=this.element,n=this.options,i=this.audio;i.pause(),i.currentTime=0,this._fireEvent("audioEnd",{src:n.audioSrc,audio:i}),a.exec(e,[i],t[0])},changeAttribute:function(e){var t,n,i=this.element,s=this.options,a=this.audio;"data-audio-src"===e&&(t=i.attr("data-audio-src"))&&""!==t.trim()&&(s.audioSrc=t,a.src=t),"data-audio-volume"===e&&(n=parseFloat(i.attr("data-audio-volume")),isNaN(n)||(s.audioVolume=n,a.volume=n))},destroy:function(){this.element.off(s.events.click,{ns:this.id})}}),s.playSound=function(e){var t,n="string"==typeof e?e:e.audioSrc,i=e&&e.audioVolume?e.audioVolume:.5;n&&((t=new Audio(n)).volume=parseFloat(i),t.addEventListener("loadeddata",function(){e&&e.onAudioStart&&a.exec(e.onAudioStart,[n],this),this.play()}),t.addEventListener("ended",function(){e&&e.onAudioEnd&&a.exec(e.onAudioEnd,[null],this)}))}}(Metro,m4q),function(h,p){"use strict";var o=h.utils,n={audioDeferred:0,playlist:null,src:null,volume:.5,loop:!1,autoplay:!1,showLoop:!0,showPlay:!0,showStop:!0,showMute:!0,showFull:!0,showStream:!0,showVolume:!0,showInfo:!0,showPlaylist:!0,showNext:!0,showPrev:!0,showFirst:!0,showLast:!0,showForward:!0,showBackward:!0,showShuffle:!0,showRandom:!0,loopIcon:"<span class='default-icon-loop'></span>",stopIcon:"<span class='default-icon-stop'></span>",playIcon:"<span class='default-icon-play'></span>",pauseIcon:"<span class='default-icon-pause'></span>",muteIcon:"<span class='default-icon-mute'></span>",volumeLowIcon:"<span class='default-icon-low-volume'></span>",volumeMediumIcon:"<span class='default-icon-medium-volume'></span>",volumeHighIcon:"<span class='default-icon-high-volume'></span>",playlistIcon:"<span class='default-icon-playlist'></span>",nextIcon:"<span class='default-icon-next'></span>",prevIcon:"<span class='default-icon-prev'></span>",firstIcon:"<span class='default-icon-first'></span>",lastIcon:"<span class='default-icon-last'></span>",forwardIcon:"<span class='default-icon-forward'></span>",backwardIcon:"<span class='default-icon-backward'></span>",shuffleIcon:"<span class='default-icon-shuffle'></span>",randomIcon:"<span class='default-icon-random'></span>",onPlay:h.noop,onPause:h.noop,onStop:h.noop,onEnd:h.noop,onMetadata:h.noop,onTime:h.noop,onAudioPlayerCreate:h.noop};h.audioPlayerSetup=function(e){n=p.extend({},n,e)},window.metroAudioPlayerSetup,h.audioPlayerSetup(window.metroAudioPlayerSetup),h.Component("audio-player",{init:function(e,t){return this._super(t,e,n,{preloader:null,player:null,audio:t,stream:null,volume:null,volumeBackup:0,muted:!1}),this},_create:function(){var e=this.element,t=this.options;this._createPlayer(),this._createControls(),this._createEvents(),!0===t.autoplay&&this.play(),this._fireEvent("audio-player-create",{element:e,player:this.player})},_createPlayer:function(){var e=this.element,t=this.options,n=this.audio,i=e.prev(),s=e.parent(),a=p("<div>").addClass("media-player audio-player "+e[0].className);0===i.length?s.prepend(a):a.insertAfter(i),e.appendTo(a),p.each(["muted","autoplay","controls","height","width","loop","poster","preload"],function(){e.removeAttr(this)}),e.attr("preload","auto"),n.volume=t.volume,null!==t.src&&this._setSource(t.src),e[0].className="",this.player=a},_setSource:function(e){var t=this.element;t.find("source").remove(),t.removeAttr("src"),Array.isArray(e)?p.each(e,function(){void 0!==this.src&&p("<source>").attr("src",this.src).attr("type",void 0!==this.type?this.type:"").appendTo(t)}):t.attr("src",e)},_createControls:function(){var e,t=this,n=this.element,i=this.options,s=this.elem,a=p("<div>").addClass("controls").addClass(i.clsControls).insertAfter(n),o=p("<div>").addClass("stream").appendTo(a),r=p("<input>").addClass("stream-slider ultra-thin cycle-marker").appendTo(o),l=p("<div>").addClass("load-audio").appendTo(o),c=p("<div>").addClass("volume").appendTo(a),d=p("<input>").addClass("volume-slider ultra-thin cycle-marker").appendTo(c),u=p("<div>").addClass("info-box").appendTo(a);!0!==i.showInfo&&u.hide(),l.activity({type:"metro",style:"color"}),l.hide(0),this.preloader=l,h.makePlugin(r,"slider",{clsMarker:"bg-red",clsHint:"bg-cyan fg-white",clsComplete:"bg-cyan",hint:!0,onStart:function(){s.paused||s.pause()},onStop:function(e){0<s.seekable.length&&(s.currentTime=(t.duration*e/100).toFixed(0)),s.paused&&0<s.currentTime&&s.play()}}),this.stream=r,!0!==i.showStream&&o.hide(),h.makePlugin(d,"slider",{clsMarker:"bg-red",clsHint:"bg-cyan fg-white",hint:!0,value:100*i.volume,onChangeValue:function(e){s.volume=e/100}}),this.volume=d,!0!==i.showVolume&&c.hide(),!0===i.showLoop&&(e=p("<button>").attr("type","button").addClass("button square loop").html(i.loopIcon).appendTo(a)),!0===i.showPlay&&p("<button>").attr("type","button").addClass("button square play").html(i.playIcon).appendTo(a),!0===i.showStop&&p("<button>").attr("type","button").addClass("button square stop").html(i.stopIcon).appendTo(a),!0===i.showMute&&p("<button>").attr("type","button").addClass("button square mute").html(i.muteIcon).appendTo(a),!0===i.loop&&(e.addClass("active"),n.attr("loop","loop")),this._setVolume(),i.muted&&(t.volumeBackup=s.volume,h.getPlugin(t.volume,"slider").val(0),s.volume=0),u.html("00:00 / 00:00")},_createEvents:function(){var t=this,n=this.element,i=this.options,s=this.elem,a=this.player;n.on("loadstart",function(){t.preloader.fadeIn()}),n.on("loadedmetadata",function(){t.duration=s.duration.toFixed(0),t._setInfo(0,t.duration),o.exec(i.onMetadata,[s,a],n[0])}),n.on("canplay",function(){t._setBuffer(),t.preloader.fadeOut()}),n.on("progress",function(){t._setBuffer()}),n.on("timeupdate",function(){var e=Math.round(100*s.currentTime/t.duration);t._setInfo(s.currentTime,t.duration),h.getPlugin(t.stream,"slider").val(e),o.exec(i.onTime,[s.currentTime,t.duration,s,a],n[0])}),n.on("waiting",function(){t.preloader.fadeIn()}),n.on("loadeddata",function(){}),n.on("play",function(){a.find(".play").html(i.pauseIcon),o.exec(i.onPlay,[s,a],n[0])}),n.on("pause",function(){a.find(".play").html(i.playIcon),o.exec(i.onPause,[s,a],n[0])}),n.on("stop",function(){h.getPlugin(t.stream,"slider").val(0),o.exec(i.onStop,[s,a],n[0])}),n.on("ended",function(){h.getPlugin(t.stream,"slider").val(0),o.exec(i.onEnd,[s,a],n[0])}),n.on("volumechange",function(){t._setVolume()}),a.on(h.events.click,".play",function(){s.paused?t.play():t.pause()}),a.on(h.events.click,".stop",function(){t.stop()}),a.on(h.events.click,".mute",function(){t._toggleMute()}),a.on(h.events.click,".loop",function(){t._toggleLoop()})},_toggleLoop:function(){var e=this.player.find(".loop");0!==e.length&&(e.toggleClass("active"),e.hasClass("active")?this.element.attr("loop","loop"):this.element.removeAttr("loop"))},_toggleMute:function(){this.muted=!this.muted,!1===this.muted?this.audio.volume=this.volumeBackup:(this.volumeBackup=this.audio.volume,this.audio.volume=0),h.getPlugin(this.volume,"slider").val(!1===this.muted?100*this.volumeBackup:0)},_setInfo:function(e,t){this.player.find(".info-box").html(o.secondsToFormattedString(Math.round(e))+" / "+o.secondsToFormattedString(Math.round(t)))},_setBuffer:function(){var e=this.audio.buffered.length?Math.round(Math.floor(this.audio.buffered.end(0))/Math.floor(this.audio.duration)*100):0;h.getPlugin(this.stream,"slider").buff(e)},_setVolume:function(){var e=this.audio,t=this.player,n=this.options,i=t.find(".mute"),s=100*e.volume;1<s&&s<30?i.html(n.volumeLowIcon):30<=s&&s<60?i.html(n.volumeMediumIcon):60<=s&&s<=100?i.html(n.volumeHighIcon):i.html(n.muteIcon)},play:function(e){void 0!==e&&this._setSource(e),void 0===this.element.attr("src")&&0===this.element.find("source").length||this.audio.play()},pause:function(){this.audio.pause()},resume:function(){this.audio.paused&&this.play()},stop:function(){this.audio.pause(),this.audio.currentTime=0,h.getPlugin(this.stream,"slider").val(0)},setVolume:function(e){if(void 0===e)return this.audio.volume;1<e&&(e/=100),this.audio.volume=e,h.getPlugin(this.volume,"slider").val(100*e)},loop:function(){this._toggleLoop()},mute:function(){this._toggleMute()},changeSource:function(){var e=JSON.parse(this.element.attr("data-src"));this.play(e)},changeVolume:function(){var e=this.element.attr("data-volume");this.setVolume(e)},changeAttribute:function(e){switch(e){case"data-src":this.changeSource();break;case"data-volume":this.changeVolume()}},destroy:function(){var e=this.element,t=this.player;return e.off("all"),t.off("all"),h.getPlugin(this.stream,"slider").destroy(),h.getPlugin(this.volume,"slider").destroy(),e}})}(Metro,m4q),function(n,i){"use strict";var s=n.utils,a={bottomsheetDeferred:0,mode:"list",toggle:null,onOpen:n.noop,onClose:n.noop,onBottomSheetCreate:n.noop};n.bottomSheetSetup=function(e){a=i.extend({},a,e)},window.metroBottomSheetSetup,n.bottomSheetSetup(window.metroBottomSheetSetup),n.Component("bottom-sheet",{init:function(e,t){return this._super(t,e,a,{toggle:null}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("bottom-sheet-create",{element:e})},_createStructure:function(){var e=this.element,t=this.options;e.addClass("bottom-sheet").addClass(t.mode+"-list"),s.isValue(t.toggle)&&0<i(t.toggle).length&&(this.toggle=i(t.toggle))},_createEvents:function(){var e=this,t=this.element;s.isValue(this.toggle)&&this.toggle.on(n.events.click,function(){e.toggle()}),t.on(n.events.click,"li",function(){e.close()})},isOpen:function(){return this.element.hasClass("opened")},open:function(e){var t=this.element;s.isValue(e)&&t.removeClass("list-style grid-style").addClass(e+"-style"),this.element.addClass("opened"),this._fireEvent("open",{element:t})},close:function(){var e=this.element;e.removeClass("opened"),this._fireEvent("close",{element:e})},toggle:function(e){this.isOpen()?this.close():this.open(e)},changeAttribute:function(e){},destroy:function(){var e=this.element;return s.isValue(this.toggle)&&this.toggle.off(n.events.click),e.off(n.events.click,"li"),e}}),n.bottomsheet={isBottomSheet:function(e){return s.isMetroObject(e,"bottom-sheet")},open:function(e,t){if(!this.isBottomSheet(e))return!1;n.getPlugin(e,"bottom-sheet").open(t)},close:function(e){if(!this.isBottomSheet(e))return!1;n.getPlugin(e,"bottom-sheet").close()},toggle:function(e,t){if(!this.isBottomSheet(e))return!1;this.isOpen(e)?this.close(e):this.open(e,t)},isOpen:function(e){return!!this.isBottomSheet(e)&&n.getPlugin(e,"bottom-sheet").isOpen()}}}(Metro,m4q),function(s,a){"use strict";var n=s.utils,i={buttongroupDeferred:0,targets:"button",clsActive:"",requiredButton:!1,mode:s.groupMode.ONE,onButtonClick:s.noop,onButtonGroupCreate:s.noop};s.buttonGroupSetup=function(e){i=a.extend({},i,e)},window.metroButtonGroupSetup,s.buttonGroupSetup(window.metroButtonGroupSetup),s.Component("button-group",{init:function(e,t){return this._super(t,e,i,{active:null,id:n.elementId("button-group")}),this},_create:function(){var e=this.element;this._createGroup(),this._createEvents(),this._fireEvent("button-group-create",{element:e})},_createGroup:function(){var e,t,n=this.element,i=this.options;n.addClass("button-group"),e=n.find(i.targets),t=n.find(".active"),i.mode===s.groupMode.ONE&&0===t.length&&!0===i.requiredButton&&a(e[0]).addClass("active"),i.mode===s.groupMode.ONE&&1<t.length&&(e.removeClass("active").removeClass(i.clsActive),a(e[0]).addClass("active")),n.find(".active").addClass("js-active").addClass(i.clsActive)},_createEvents:function(){var t=this,n=this.element,i=this.options;n.on(s.events.click,i.targets,function(){var e=a(this);t._fireEvent("button-click",{button:this}),i.mode===s.groupMode.ONE&&e.hasClass("active")||(i.mode===s.groupMode.ONE?(n.find(i.targets).removeClass(i.clsActive).removeClass("active js-active"),e.addClass("active").addClass(i.clsActive).addClass("js-active")):e.toggleClass("active").toggleClass(i.clsActive).toggleClass("js-active"))})},changeAttribute:function(e){},destroy:function(){var e=this.element,t=this.options;return e.off(s.events.click,t.targets),e}})}(Metro,m4q),function(n,b){"use strict";var y=n.utils,i={calendarDeferred:0,dayBorder:!1,excludeDay:null,prevMonthIcon:"<span class='default-icon-chevron-left'></span>",nextMonthIcon:"<span class='default-icon-chevron-right'></span>",prevYearIcon:"<span class='default-icon-chevron-left'></span>",nextYearIcon:"<span class='default-icon-chevron-right'></span>",compact:!1,wide:!1,widePoint:null,pickerMode:!1,show:null,locale:METRO_LOCALE,weekStart:METRO_WEEK_START,outside:!0,buttons:"cancel, today, clear, done",yearsBefore:100,yearsAfter:100,headerFormat:"%A, %b %e",showHeader:!0,showFooter:!0,showTimeField:!0,showWeekNumber:!1,clsCalendar:"",clsCalendarHeader:"",clsCalendarContent:"",clsCalendarFooter:"",clsCalendarMonths:"",clsCalendarYears:"",clsToday:"",clsSelected:"",clsExcluded:"",clsCancelButton:"",clsTodayButton:"",clsClearButton:"",clsDoneButton:"",isDialog:!1,ripple:!1,rippleColor:"#cccccc",exclude:null,preset:null,minDate:null,maxDate:null,weekDayClick:!1,weekNumberClick:!1,multiSelect:!1,special:null,format:METRO_DATE_FORMAT,inputFormat:null,onCancel:n.noop,onToday:n.noop,onClear:n.noop,onDone:n.noop,onDayClick:n.noop,onDayDraw:n.noop,onWeekDayClick:n.noop,onWeekNumberClick:n.noop,onMonthChange:n.noop,onYearChange:n.noop,onCalendarCreate:n.noop};n.calendarSetup=function(e){i=b.extend({},i,e)},window.metroCalendarSetup,n.calendarSetup(window.metroCalendarSetup),n.Component("calendar",{init:function(e,t){var n=new Date;return n.setHours(0,0,0,0),this._super(t,e,i,{today:n,show:n,current:{year:n.getFullYear(),month:n.getMonth(),day:n.getDate()},preset:[],selected:[],exclude:[],special:[],excludeDay:[],min:null,max:null,locale:null,minYear:null,maxYear:null,offset:null,id:y.elementId("calendar")}),this},_create:function(){var e=this.element,t=this.options;this.minYear=this.current.year-this.options.yearsBefore,this.maxYear=this.current.year+this.options.yearsAfter,this.offset=(new Date).getTimezoneOffset()/60+1,e.html("").addClass("calendar "+(!0===t.compact?"compact":"")).addClass(t.clsCalendar),!0===t.dayBorder&&e.addClass("day-border"),y.isValue(t.excludeDay)&&(this.excludeDay=(""+t.excludeDay).toArray(",","int")),y.isValue(t.preset)&&this._dates2array(t.preset,"selected"),y.isValue(t.exclude)&&this._dates2array(t.exclude,"exclude"),y.isValue(t.special)&&this._dates2array(t.special,"special"),!1!==t.buttons&&!1===Array.isArray(t.buttons)&&(t.buttons=t.buttons.split(",").map(function(e){return e.trim()})),null!==t.minDate&&y.isDate(t.minDate,t.inputFormat)&&(this.min=y.isValue(t.inputFormat)?t.minDate.toDate(t.inputFormat):new Date(t.minDate)),null!==t.maxDate&&y.isDate(t.maxDate,t.inputFormat)&&(this.max=y.isValue(t.inputFormat)?t.maxDate.toDate(t.inputFormat):new Date(t.maxDate)),null!==t.show&&y.isDate(t.show,t.inputFormat)&&(this.show=y.isValue(t.inputFormat)?t.show.toDate(t.inputFormat):new Date(t.show),this.show.setHours(0,0,0,0),this.current={year:this.show.getFullYear(),month:this.show.getMonth(),day:this.show.getDate()}),this.locale=void 0!==n.locales[t.locale]?n.locales[t.locale]:n.locales["en-US"],this._drawCalendar(),this._createEvents(),!0===t.wide?e.addClass("calendar-wide"):!y.isNull(t.widePoint)&&y.mediaExist(t.widePoint)&&e.addClass("calendar-wide"),!0===t.ripple&&!1!==y.isFunc(e.ripple)&&e.ripple({rippleTarget:".button, .prev-month, .next-month, .prev-year, .next-year, .day",rippleColor:this.options.rippleColor}),this._fireEvent("calendar-create",{element:e})},_dates2array:function(e,t){var n,i=this,s=this.options;y.isNull(e)||(n="string"==typeof e?e.toArray():e,b.each(n,function(){var e;if(y.isDateObject(this))e=this;else{if(e=y.isValue(s.inputFormat)?this.toDate(s.inputFormat):new Date(this),!1===y.isDate(e))return;e.setHours(0,0,0,0)}i[t].push(e.getTime())}))},_createEvents:function(){var s=this,a=this.element,o=this.options;b(window).on(n.events.resize,function(){!0!==o.wide&&(!y.isNull(o.widePoint)&&y.mediaExist(o.widePoint)?a.addClass("calendar-wide"):a.removeClass("calendar-wide"))},{ns:this.id}),a.on(n.events.click,function(){var e=a.find(".calendar-months"),t=a.find(".calendar-years");e.hasClass("open")&&e.removeClass("open"),t.hasClass("open")&&t.removeClass("open")}),a.on(n.events.click,".prev-month, .next-month, .prev-year, .next-year",function(){var e,t=b(this);t.hasClass("prev-month")&&(e=new Date(s.current.year,s.current.month-1,1)).getFullYear()<s.minYear||t.hasClass("next-month")&&(e=new Date(s.current.year,s.current.month+1,1)).getFullYear()>s.maxYear||t.hasClass("prev-year")&&(e=new Date(s.current.year-1,s.current.month,1)).getFullYear()<s.minYear||t.hasClass("next-year")&&(e=new Date(s.current.year+1,s.current.month,1)).getFullYear()>s.maxYear||(s.current={year:e.getFullYear(),month:e.getMonth(),day:e.getDate()},setTimeout(function(){s._drawContent(),(t.hasClass("prev-month")||t.hasClass("next-month"))&&(y.exec(o.onMonthChange,[s.current,a],a[0]),a.fire("monthchange",{current:s.current})),(t.hasClass("prev-year")||t.hasClass("next-year"))&&(y.exec(o.onYearChange,[s.current,a],a[0]),a.fire("yearchange",{current:s.current}))},o.ripple?300:1))}),a.on(n.events.click,".button.today",function(){s.toDay(),y.exec(o.onToday,[s.today,a]),a.fire("today",{today:s.today})}),a.on(n.events.click,".button.clear",function(){s.selected=[],s._drawContent(),y.exec(o.onClear,[a]),a.fire("clear")}),a.on(n.events.click,".button.cancel",function(){s._drawContent(),y.exec(o.onCancel,[a]),a.fire("cancel")}),a.on(n.events.click,".button.done",function(){s._drawContent(),y.exec(o.onDone,[s.selected,a]),a.fire("done")}),!0===o.weekDayClick&&a.on(n.events.click,".week-days .day",function(e){var t,n,i;n=(t=b(this)).index(),!0===o.multiSelect&&(i=!0===o.outside?a.find(".days-row .day:nth-child("+(n+1)+")"):a.find(".days-row .day:not(.outside):nth-child("+(n+1)+")"),b.each(i,function(){var e=b(this),t=e.data("day");e.hasClass("disabled")||e.hasClass("excluded")||(s.selected.contains(t)||s.selected.push(t),e.addClass("selected").addClass(o.clsSelected))})),y.exec(o.onWeekDayClick,[s.selected,t],a[0]),a.fire("weekdayclick",{day:t,selected:s.selected}),e.preventDefault(),e.stopPropagation()}),o.weekNumberClick&&a.on(n.events.click,".days-row .week-number",function(e){var t,n,i;n=(t=b(this)).text(),!0===o.multiSelect&&(i=b(this).siblings(".day"),b.each(i,function(){var e=b(this),t=e.data("day");e.hasClass("disabled")||e.hasClass("excluded")||(s.selected.contains(t)||s.selected.push(t),e.addClass("selected").addClass(o.clsSelected))})),y.exec(o.onWeekNumberClick,[s.selected,n,t],a[0]),a.fire("weeknumberclick",{el:this,num:n,selected:s.selected}),e.preventDefault(),e.stopPropagation()}),a.on(n.events.click,".days-row .day",function(e){var t,n,i=b(this);if(n=i.data("day"),t=s.selected.indexOf(n),i.hasClass("outside"))return n=new Date(n),s.current={year:n.getFullYear(),month:n.getMonth(),day:n.getDate()},void s._drawContent();i.hasClass("disabled")||(!0===o.pickerMode?(s.selected=[n],s.today=new Date(n),s.current.year=s.today.getFullYear(),s.current.month=s.today.getMonth(),s.current.day=s.today.getDate(),s._drawHeader(),s._drawContent()):-1===t?(!1===o.multiSelect&&(a.find(".days-row .day").removeClass("selected").removeClass(o.clsSelected),s.selected=[]),s.selected.push(n),i.addClass("selected").addClass(o.clsSelected)):(i.removeClass("selected").removeClass(o.clsSelected),y.arrayDelete(s.selected,n))),y.exec(o.onDayClick,[s.selected,i,a]),a.fire("dayclick",{day:i,selected:s.selected}),e.preventDefault(),e.stopPropagation()}),a.on(n.events.click,".curr-month",function(e){var t,n=a.find(".months-list");n.find(".active").removeClass("active"),n.scrollTop(0),a.find(".calendar-months").addClass("open"),t=n.find(".js-month-"+s.current.month).addClass("active"),setTimeout(function(){n.animate({draw:{scrollTop:t.position().top-(n.height()-t.height())/2},dur:200})},300),e.preventDefault(),e.stopPropagation()}),a.on(n.events.click,".calendar-months li",function(e){s.current.month=b(this).index(),s._drawContent(),y.exec(o.onMonthChange,[s.current,a],a[0]),a.fire("monthchange",{current:s.current}),a.find(".calendar-months").removeClass("open"),e.preventDefault(),e.stopPropagation()}),a.on(n.events.click,".curr-year",function(e){var t,n=a.find(".years-list");n.find(".active").removeClass("active"),n.scrollTop(0),a.find(".calendar-years").addClass("open"),t=n.find(".js-year-"+s.current.year).addClass("active"),setTimeout(function(){n.animate({draw:{scrollTop:t.position().top-(n.height()-t.height())/2},dur:200})},300),e.preventDefault(),e.stopPropagation()}),a.on(n.events.click,".calendar-years li",function(e){s.current.year=b(this).text(),s._drawContent(),y.exec(o.onYearChange,[s.current,a],a[0]),a.fire("yearchange",{current:s.current}),a.find(".calendar-years").removeClass("open"),e.preventDefault(),e.stopPropagation()})},_drawHeader:function(){var e=this.element,t=this.options,n=e.find(".calendar-header");0===n.length&&(n=b("<div>").addClass("calendar-header").addClass(t.clsCalendarHeader).appendTo(e)),n.html(""),b("<div>").addClass("header-year").html(this.today.getFullYear()).appendTo(n),b("<div>").addClass("header-day").html(this.today.format(t.headerFormat,t.locale)).appendTo(n),!1===t.showHeader&&n.hide()},_drawFooter:function(){var e=this.element,t=this.options,n=this.locale.buttons,i=e.find(".calendar-footer");!1!==t.buttons&&(0===i.length&&(i=b("<div>").addClass("calendar-footer").addClass(t.clsCalendarFooter).appendTo(e)),i.html(""),b.each(t.buttons,function(){var e=b("<button>").attr("type","button").addClass("button "+this+" "+t["cls"+this.capitalize()+"Button"]).html(n[this]).appendTo(i);"cancel"!==this&&"done"!==this||e.addClass("js-dialog-close")}),!1===t.showFooter&&i.hide())},_drawMonths:function(){var e,t=this.element,n=this.options,i=b("<div>").addClass("calendar-months").addClass(n.clsCalendarMonths).appendTo(t),s=b("<ul>").addClass("months-list").appendTo(i),a=this.locale.calendar;for(e=0;e<12;e++)b("<li>").addClass("js-month-"+e).html(a.months[e]).appendTo(s)},_drawYears:function(){var e,t=this.element,n=this.options,i=b("<div>").addClass("calendar-years").addClass(n.clsCalendarYears).appendTo(t),s=b("<ul>").addClass("years-list").appendTo(i);for(e=this.minYear;e<=this.maxYear;e++)b("<li>").addClass("js-year-"+e).html(e).appendTo(s)},_drawContent:function(){var e,t,n,i,s,a,o,r,l=this.element,c=this.options,d=l.find(".calendar-content"),u=this.locale.calendar,h=0,p=new Date(this.current.year,this.current.month,1),f=new Date(this.current.year,this.current.month,0).getDate();0===d.length&&(d=b("<div>").addClass("calendar-content").addClass(c.clsCalendarContent).appendTo(l)),d.html(""),e=b("<div>").addClass("calendar-toolbar").appendTo(d),b("<span>").addClass("prev-month").html(c.prevMonthIcon).appendTo(e),b("<span>").addClass("curr-month").html(u.months[this.current.month]).appendTo(e),b("<span>").addClass("next-month").html(c.nextMonthIcon).appendTo(e),b("<span>").addClass("prev-year").html(c.prevYearIcon).appendTo(e),b("<span>").addClass("curr-year").html(this.current.year).appendTo(e),b("<span>").addClass("next-year").html(c.nextYearIcon).appendTo(e);var m=b("<div>").addClass("week-days").appendTo(d),v="day";for(!0===c.showWeekNumber&&(b("<span>").addClass("week-number").html("#").appendTo(m),v+=" and-week-number"),t=0;t<7;t++)0===c.weekStart?n=t:7===(n=t+1)&&(n=0),b("<span>").addClass(v).html(u.days[n+7]).appendTo(m);var g=b("<div>").addClass("days").appendTo(d),w=b("<div>").addClass("days-row").appendTo(g);for(a=0===c.weekStart?p.getDay():0===p.getDay()?6:p.getDay()-1,o=this.current.month-1<0?(r=11,this.current.year-1):(r=this.current.month-1,this.current.year),!0===c.showWeekNumber&&b("<div>").addClass("week-number").html(new Date(o,r,f-a+1).getWeek(c.weekStart)).appendTo(w),t=0;t<a;t++){var C=f-a+t+1;i=b("<div>").addClass(v+" outside").appendTo(w),(s=new Date(o,r,C)).setHours(0,0,0,0),i.data("day",s.getTime()),!0===c.outside&&(i.html(C),0<this.excludeDay.length&&-1<this.excludeDay.indexOf(s.getDay())&&i.addClass("disabled excluded").addClass(c.clsExcluded),y.exec(c.onDayDraw,[s],i[0]),l.fire("daydraw",{cell:i[0],date:s})),h++}for(p.setHours(0,0,0,0);p.getMonth()===this.current.month;)(i=b("<div>").addClass(v).html(p.getDate()).appendTo(w)).data("day",p.getTime()),this.show.getTime()===p.getTime()&&i.addClass("showed"),this.today.getTime()===p.getTime()&&i.addClass("today").addClass(c.clsToday),0===this.special.length?(-1!==this.selected.indexOf(p.getTime())&&i.addClass("selected").addClass(c.clsSelected),-1!==this.exclude.indexOf(p.getTime())&&i.addClass("disabled excluded").addClass(c.clsExcluded),null!==this.min&&p.getTime()<this.min.getTime()&&i.addClass("disabled excluded").addClass(c.clsExcluded),null!==this.max&&p.getTime()>this.max.getTime()&&i.addClass("disabled excluded").addClass(c.clsExcluded),0<this.excludeDay.length&&-1<this.excludeDay.indexOf(p.getDay())&&i.addClass("disabled excluded").addClass(c.clsExcluded)):-1===this.special.indexOf(p.getTime())&&i.addClass("disabled excluded").addClass(c.clsExcluded),y.exec(c.onDayDraw,[p],i[0]),l.fire("daydraw",{cell:i[0],date:p}),++h%7==0&&(w=b("<div>").addClass("days-row").appendTo(g),!0===c.showWeekNumber&&b("<div>").addClass("week-number").html(new Date(p.getFullYear(),p.getMonth(),p.getDate()+1).getWeek(c.weekStart)).appendTo(w)),p.setDate(p.getDate()+1),p.setHours(0,0,0,0);if(a=0===c.weekStart?p.getDay():0===p.getDay()?6:p.getDay()-1,o=11<this.current.month+1?(r=0,this.current.year+1):(r=this.current.month+1,this.current.year),0<a)for(t=0;t<7-a;t++)i=b("<div>").addClass(v+" outside").appendTo(w),(s=new Date(o,r,t+1)).setHours(0,0,0,0),i.data("day",s.getTime()),!0===c.outside&&(i.html(t+1),0<this.excludeDay.length&&-1<this.excludeDay.indexOf(s.getDay())&&i.addClass("disabled excluded").addClass(c.clsExcluded),y.exec(c.onDayDraw,[s],i[0]),l.fire("daydraw",{cell:i[0],date:s}))},_drawCalendar:function(){var e=this;setTimeout(function(){e.element.html(""),e._drawHeader(),e._drawContent(),e._drawFooter(),e._drawMonths(),e._drawYears()},0)},getPreset:function(){return this.preset},getSelected:function(){return this.selected},getExcluded:function(){return this.exclude},getToday:function(){return this.today},getCurrent:function(){return this.current},clearSelected:function(){this.selected=[],this._drawContent()},toDay:function(){this.today=new Date,this.today.setHours(0,0,0,0),this.current={year:this.today.getFullYear(),month:this.today.getMonth(),day:this.today.getDate()},this._drawHeader(),this._drawContent()},setExclude:function(e){var t=this.element,n=this.options;y.isNull(e)&&y.isNull(t.attr("data-exclude"))||(n.exclude=y.isNull(e)?t.attr("data-exclude"):e,this._dates2array(n.exclude,"exclude"),this._drawContent())},setPreset:function(e){var t=this.element,n=this.options;y.isNull(e)&&y.isNull(t.attr("data-preset"))||(n.preset=y.isNull(e)?t.attr("data-preset"):e,this._dates2array(n.preset,"selected"),this._drawContent())},setSpecial:function(e){var t=this.element,n=this.options;y.isNull(e)&&y.isNull(t.attr("data-special"))||(n.special=y.isNull(e)?t.attr("data-special"):e,this._dates2array(n.exclude,"special"),this._drawContent())},setShow:function(e){var t=this.element,n=this.options;y.isNull(e)&&y.isNull(t.attr("data-show"))||(n.show=y.isNull(e)?t.attr("data-show"):e,this.show=y.isDateObject(e)?e:y.isValue(n.inputFormat)?n.show.toDate(n.inputFormat):new Date(n.show),this.show.setHours(0,0,0,0),this.current={year:this.show.getFullYear(),month:this.show.getMonth(),day:this.show.getDate()},this._drawContent())},setMinDate:function(e){var t=this.element,n=this.options;n.minDate=y.isValue(e)?e:t.attr("data-min-date"),y.isValue(n.minDate)&&y.isDate(n.minDate,n.inputFormat)&&(this.min=y.isValue(n.inputFormat)?n.minDate.toDate(n.inputFormat):new Date(n.minDate)),this._drawContent()},setMaxDate:function(e){var t=this.element,n=this.options;n.maxDate=y.isValue(e)?e:t.attr("data-max-date"),y.isValue(n.maxDate)&&y.isDate(n.maxDate,n.inputFormat)&&(this.max=y.isValue(n.inputFormat)?n.maxDate.toDate(n.inputFormat):new Date(n.maxDate)),this._drawContent()},setToday:function(e){var t=this.options;y.isValue(e)||(e=new Date),this.today=y.isDateObject(e)?e:y.isValue(t.inputFormat)?e.toDate(t.inputFormat):new Date(e),this.today.setHours(0,0,0,0),this._drawHeader(),this._drawContent()},i18n:function(e){var t=this.options;return void 0===e?t.locale:void 0!==n.locales[e]&&(t.locale=e,this.locale=n.locales[t.locale],void this._drawCalendar())},changeAttrLocale:function(){var e=this.element;this.i18n(e.attr("data-locale"))},changeAttribute:function(e){switch(e){case"data-exclude":this.setExclude();break;case"data-preset":this.setPreset();break;case"data-special":this.setSpecial();break;case"data-show":this.setShow();break;case"data-min-date":this.setMinDate();break;case"data-max-date":this.setMaxDate();break;case"data-locale":this.changeAttrLocale()}},destroy:function(){var e=this.element,t=this.options;return e.off(n.events.click,".prev-month, .next-month, .prev-year, .next-year"),e.off(n.events.click,".button.today"),e.off(n.events.click,".button.clear"),e.off(n.events.click,".button.cancel"),e.off(n.events.click,".button.done"),e.off(n.events.click,".week-days .day"),e.off(n.events.click,".days-row .day"),e.off(n.events.click,".curr-month"),e.off(n.events.click,".calendar-months li"),e.off(n.events.click,".curr-year"),e.off(n.events.click,".calendar-years li"),e.off(n.events.click),!0===t.ripple&&e.data("ripple").destroy(),b(window).off(n.events.resize,{ns:this.id}),e}}),b(document).on(n.events.click,function(){b(".calendar .calendar-years").each(function(){b(this).removeClass("open")}),b(".calendar .calendar-months").each(function(){b(this).removeClass("open")})})}(Metro,m4q),function(l,c){"use strict";var d=l.utils,n={value:"",calendarpickerDeferred:0,nullValue:!0,useNow:!1,prepend:"",calendarWide:!1,calendarWidePoint:null,dialogMode:!1,dialogPoint:640,dialogOverlay:!0,overlayColor:"#000000",overlayAlpha:.5,locale:METRO_LOCALE,size:"100%",format:METRO_DATE_FORMAT,inputFormat:null,headerFormat:"%A, %b %e",clearButton:!1,calendarButtonIcon:"<span class='default-icon-calendar'></span>",clearButtonIcon:"<span class='default-icon-cross'></span>",copyInlineStyles:!1,clsPicker:"",clsInput:"",yearsBefore:100,yearsAfter:100,weekStart:METRO_WEEK_START,outside:!0,ripple:!1,rippleColor:"#cccccc",exclude:null,minDate:null,maxDate:null,special:null,showHeader:!0,showWeekNumber:!1,clsCalendar:"",clsCalendarHeader:"",clsCalendarContent:"",clsCalendarMonths:"",clsCalendarYears:"",clsToday:"",clsSelected:"",clsExcluded:"",clsPrepend:"",onDayClick:l.noop,onCalendarPickerCreate:l.noop,onCalendarShow:l.noop,onCalendarHide:l.noop,onChange:l.noop,onMonthChange:l.noop,onYearChange:l.noop};l.calendarPickerSetup=function(e){n=c.extend({},n,e)},window.metroCalendarPickerSetup,l.calendarPickerSetup(window.metroCalendarPickerSetup),l.Component("calendar-picker",{init:function(e,t){return this._super(t,e,n,{value:null,value_date:null,calendar:null,overlay:null,id:d.elementId("calendar-picker")}),this},_create:function(){this._createStructure(),this._createEvents(),this._fireEvent("calendar-picker-create",{element:this.element})},_createStructure:function(){var e,s=this,a=this.element,o=this.options,n=c("<div>").addClass("input "+a[0].className+" calendar-picker"),t=c("<div>").addClass("button-group"),r=c("<div>").addClass("drop-shadow"),i=c("body");a.attr("type","text"),a.attr("autocomplete","off"),a.attr("readonly",!0),e=""!==(""+o.value).trim()?o.value:a.val().trim(),d.isValue(e)?this.value=d.isValue(o.inputFormat)?e.toDate(o.inputFormat,o.locale):new Date(e):o.useNow&&(this.value=new Date),d.isValue(this.value)&&this.value.setHours(0,0,0,0),a.val(d.isValue(e)||!0!==o.nullValue?s.value.format(o.format,o.locale):""),n.insertBefore(a),a.appendTo(n),t.appendTo(n),r.appendTo(o.dialogMode?i:n),l.makePlugin(r,"calendar",{wide:o.calendarWide,widePoint:o.calendarWidePoint,format:o.format,inputFormat:o.inputFormat,pickerMode:!0,show:o.value,locale:o.locale,weekStart:o.weekStart,outside:o.outside,buttons:!1,headerFormat:o.headerFormat,clsCalendar:[o.clsCalendar,"calendar-for-picker",o.dialogMode?"dialog-mode":""].join(" "),clsCalendarHeader:o.clsCalendarHeader,clsCalendarContent:o.clsCalendarContent,clsCalendarFooter:"d-none",clsCalendarMonths:o.clsCalendarMonths,clsCalendarYears:o.clsCalendarYears,clsToday:o.clsToday,clsSelected:o.clsSelected,clsExcluded:o.clsExcluded,ripple:o.ripple,rippleColor:o.rippleColor,exclude:o.exclude,minDate:o.minDate,maxDate:o.maxDate,yearsBefore:o.yearsBefore,yearsAfter:o.yearsAfter,special:o.special,showHeader:o.showHeader,showFooter:!1,showWeekNumber:o.showWeekNumber,onDayClick:function(e,t,n){var i=new Date(e[0]);i.setHours(0,0,0,0),s._removeOverlay(),s.value=i,a.val(i.format(o.format,o.locale)),a.trigger("change"),r.removeClass("open open-up"),r.hide(),d.exec(o.onChange,[s.value],a[0]),a.fire("change",{val:s.value}),d.exec(o.onDayClick,[e,t,n],a[0]),a.fire("dayclick",{sel:e,day:t,el:n})},onMonthChange:o.onMonthChange,onYearChange:o.onYearChange}),this.calendar=r,!0===o.clearButton&&c("<button>").addClass("button input-clear-button").attr("tabindex",-1).attr("type","button").html(o.clearButtonIcon).appendTo(t),c("<button>").addClass("button").attr("tabindex",-1).attr("type","button").html(o.calendarButtonIcon).appendTo(t),""!==o.prepend&&c("<div>").html(o.prepend).addClass("prepend").addClass(o.clsPrepend).appendTo(n);"rtl"===a.attr("dir")&&n.addClass("rtl"),-1<String(o.size).indexOf("%")?n.css({width:o.size}):n.css({width:parseInt(o.size)+"px"}),!(a[0].className="")===o.copyInlineStyles&&c.each(d.getInlineStyles(a),function(e,t){n.css(e,t)}),n.addClass(o.clsPicker),a.addClass(o.clsInput),!0===o.dialogOverlay&&(this.overlay=s._overlay()),!0===o.dialogMode?n.addClass("dialog-mode"):d.media("(max-width: "+o.dialogPoint+"px)")&&(n.addClass("dialog-mode"),this.calendar.addClass("dialog-mode")),a.is(":disabled")?this.disable():this.enable()},_createEvents:function(){var n=this,i=this.element,s=this.options,a=i.parent(),e=a.find(".input-clear-button"),o=this.calendar,r=l.getPlugin(o[0],"calendar"),t=this.calendar;c(window).on(l.events.resize,function(){!0!==s.dialogMode&&(d.media("(max-width: "+s.dialogPoint+"px)")?(a.addClass("dialog-mode"),t.appendTo("body").addClass("dialog-mode")):(a.removeClass("dialog-mode"),t.appendTo(a).removeClass("dialog-mode")))},{ns:this.id}),0<e.length&&e.on(l.events.click,function(e){i.val("").trigger("change").blur(),n.value=null,e.preventDefault(),e.stopPropagation()}),a.on(l.events.click,"button, input",function(e){var t=d.isValue(n.value)?n.value:new Date;t.setHours(0,0,0,0),!1===o.hasClass("open")&&!1===o.hasClass("open-up")?(c(".calendar-picker .calendar").removeClass("open open-up").hide(),r.setPreset([t]),r.setShow(t),r.setToday(t),a.hasClass("dialog-mode")&&n.overlay.appendTo(c("body")),o.addClass("open"),!1===d.isOutsider(o)&&o.addClass("open-up"),d.exec(s.onCalendarShow,[i,o],o),i.fire("calendarshow",{calendar:o})):(n._removeOverlay(),o.removeClass("open open-up"),d.exec(s.onCalendarHide,[i,o],o),i.fire("calendarhide",{calendar:o})),e.preventDefault(),e.stopPropagation()}),i.on(l.events.blur,function(){a.removeClass("focused")}),i.on(l.events.focus,function(){a.addClass("focused")}),i.on(l.events.change,function(){d.exec(s.onChange,[n.value],i[0])}),a.on(l.events.click,function(e){e.preventDefault(),e.stopPropagation()})},_overlay:function(){var e=this.options,t=c("<div>");return t.addClass("overlay for-calendar-picker").addClass(e.clsOverlay),"transparent"===e.overlayColor?t.addClass("transparent"):t.css({background:d.hex2rgba(e.overlayColor,e.overlayAlpha)}),t},_removeOverlay:function(){c("body").find(".overlay.for-calendar-picker").remove()},val:function(e){var t=this.element,n=this.options;if(d.isNull(e))return this.value;!0===d.isDate(e,n.inputFormat)&&(l.getPlugin(this.calendar[0],"calendar").clearSelected(),this.value="string"==typeof e?n.inputFormat?e.toDate(n.inputFormat,n.locale):new Date(e):e,d.isValue(this.value)&&this.value.setHours(0,0,0,0),t.val(this.value.format(n.format,n.locale)),t.trigger("change"))},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},i18n:function(e){var t,n=this.options,i=this.calendar;return void 0===e?n.locale:void 0!==l.locales[e]&&((t=i[0].hidden)&&i.css({visibility:"hidden",display:"block"}),l.getPlugin(i[0],"calendar").i18n(e),void(t&&i.css({visibility:"visible",display:"none"})))},changeAttribute:function(e){var t=this,n=this.element,i=l.getPlugin(this.calendar[0],"calendar");switch(e){case"value":t.val(n.attr("value"));break;case"disabled":this.toggleState();break;case"data-locale":t.i18n(n.attr("data-locale"));break;case"data-special":i.setSpecial(n.attr("data-special"));break;case"data-exclude":i.setExclude(n.attr("data-exclude"));break;case"data-min-date":i.setMinDate(n.attr("data-min-date"));break;case"data-max-date":i.setMaxDate(n.attr("data-max-date"));break;case"data-value":t.val(n.attr("data-value"))}},destroy:function(){var e=this.element,t=e.parent(),n=t.find(".input-clear-button");return c(window).off(l.events.resize,{ns:this.id}),n.off(l.events.click),t.off(l.events.click,"button, input"),e.off(l.events.blur),e.off(l.events.focus),e.off(l.events.change),l.getPlugin(this.calendar,"calendar").destroy(),e}}),c(document).on(l.events.click,".overlay.for-calendar-picker",function(){c(this).remove(),c(".calendar-for-picker.open").removeClass("open open-up")}),c(document).on(l.events.click,function(){c(".calendar-picker .calendar").removeClass("open open-up")})}(Metro,m4q),function(m,a){"use strict";var o=m.utils,v=["slide","slide-v","fade","switch","zoom","swirl"],n={carouselDeferred:0,autoStart:!1,width:"100%",height:"16/9",effect:v[0],effectFunc:"linear",direction:"left",duration:METRO_ANIMATION_DURATION,period:5e3,stopOnMouse:!0,controls:!0,bullets:!0,bulletsStyle:"square",bulletsSize:"default",controlsOnMouse:!1,controlsOutside:!1,bulletsPosition:"default",controlPrev:"&#x23F4",controlNext:"&#x23F5",clsCarousel:"",clsSlides:"",clsSlide:"",clsControls:"",clsControlNext:"",clsControlPrev:"",clsBullets:"",clsBullet:"",clsBulletOn:"",clsThumbOn:"",onStop:m.noop,onStart:m.noop,onPlay:m.noop,onSlideClick:m.noop,onBulletClick:m.noop,onThumbClick:m.noop,onMouseEnter:m.noop,onMouseLeave:m.noop,onNextClick:m.noop,onPrevClick:m.noop,onSlideShow:m.noop,onSlideHide:m.noop,onCarouselCreate:m.noop};m.carouselSetup=function(e){n=a.extend({},n,e)},window.metroCarouselSetup,m.carouselSetup(window.metroCarouselSetup),m.Component("carousel",{init:function(e,t){return this._super(t,e,n,{height:0,width:0,slides:[],current:null,currentIndex:null,dir:"left",interval:!1,isAnimate:!1,id:o.elementId("carousel")}),this},_create:function(){var e=this.element,t=this.options,n=e.find(".slide"),i=e.find(".slides");this.dir=this.options.direction,e.addClass("carousel").addClass(t.clsCarousel),!0===t.controlsOutside&&e.addClass("controls-outside"),0===i.length&&(i=a("<div>").addClass("slides").appendTo(e),n.appendTo(i)),n.addClass(t.clsSlides),0<n.length&&(this._createSlides(),this._createControls(),this._createBullets(),this._createEvents(),this._resize(),!0===t.controlsOnMouse&&(e.find("[class*=carousel-switch]").fadeOut(0),e.find(".carousel-bullets").fadeOut(0)),!0===t.autoStart?this._start():this._fireEvent("slide-show",{current:this.slides[this.currentIndex][0],prev:void 0})),this._fireEvent("carousel-create",{element:e})},_start:function(){var t=this,e=this.element,n=this.options,i=n.period,s=this.slides[this.currentIndex];void 0!==s.data("period")&&(i=s.data("period")),this.slides.length<=1||(!1===this.interval&&(this.interval=setTimeout(function(){var e="left"===n.direction?"next":"prior";t._slideTo(e,!0)},i)),this._fireEvent("start",{element:e}))},_stop:function(){clearInterval(this.interval),this.interval=!1},_resize:function(){var t,e=this.element,n=this.options,i=e.outerWidth(),s=[];-1<["16/9","21/9","4/3"].indexOf(n.height)?t=o.aspectRatioH(i,n.height):-1<String(n.height).indexOf("@")?(s=n.height.substr(1).toArray("|"),a.each(s,function(){var e=this.toArray(",");window.matchMedia(e[0]).matches&&(t=-1<["16/9","21/9","4/3"].indexOf(e[1])?o.aspectRatioH(i,e[1]):parseInt(e[1]))})):t=parseInt(n.height),e.css({height:t})},_createSlides:function(){var n=this,e=this.element,i=this.options,t=e.find(".slide");a.each(t,function(e){var t=a(this);if(void 0!==t.data("cover")&&t.css({backgroundImage:"url("+t.data("cover")+")"}),0!==e)switch(i.effect){case"switch":case"slide":t.css("left","100%");break;case"slide-v":t.css("top","100%");break;case"fade":case"zoom":case"swirl":t.css("opacity","0")}t.addClass(i.clsSlide),n.slides.push(t)}),this.currentIndex=0,this.current=this.slides[this.currentIndex]},_createControls:function(){var e,t,n=this.element,i=this.options;!1!==i.controls&&(e=a("<span/>").addClass("carousel-switch-next").addClass(i.clsControls).addClass(i.clsControlNext).html(">"),t=a("<span/>").addClass("carousel-switch-prev").addClass(i.clsControls).addClass(i.clsControlPrev).html("<"),i.controlNext&&e.html(i.controlNext),i.controlPrev&&t.html(i.controlPrev),e.appendTo(n),t.appendTo(n))},_createBullets:function(){var e,t,n=this.element,i=this.options;if(!1!==i.bullets){for(e=a("<div>").addClass("carousel-bullets").addClass(i.bulletsSize+"-size").addClass("bullet-style-"+i.bulletsStyle).addClass(i.clsBullets),"default"===i.bulletsPosition||"center"===i.bulletsPosition?e.addClass("flex-justify-center"):"left"===i.bulletsPosition?e.addClass("flex-justify-start"):e.addClass("flex-justify-end"),t=0;t<this.slides.length;t++){var s=a("<span>").addClass("carousel-bullet").addClass(i.clsBullet).data("slide",t);0===t&&s.addClass("bullet-on").addClass(i.clsBulletOn),s.appendTo(e)}e.appendTo(n)}},_createEvents:function(){var t=this,e=this.element,n=this.options;e.on(m.events.click,".carousel-bullet",function(){var e=a(this);!1===t.isAnimate&&(t._slideToSlide(e.data("slide")),t._fireEvent("bullet-click",{bullet:e}))}),e.on(m.events.click,".carousel-switch-next",function(){!1===t.isAnimate&&(t._slideTo("next",!1),t._fireEvent("next-click",{button:this}))}),e.on(m.events.click,".carousel-switch-prev",function(){!1===t.isAnimate&&(t._slideTo("prev",!1),t._fireEvent("prev-click",{button:this}))}),!0===n.stopOnMouse&&!0===n.autoStart&&(e.on(m.events.enter,function(){t._stop(),t._fireEvent("mouse-enter",{element:e},!1,!0)}),e.on(m.events.leave,function(){t._start(),t._fireEvent("mouse-leave",{element:e},!1,!0)})),!0===n.controlsOnMouse&&(e.on(m.events.enter,function(){e.find("[class*=carousel-switch]").fadeIn(),e.find(".carousel-bullets").fadeIn()}),e.on(m.events.leave,function(){e.find("[class*=carousel-switch]").fadeOut(),e.find(".carousel-bullets").fadeOut()})),e.on(m.events.click,".slide",function(){var e=a(this);t._fireEvent("slide-click",{slide:e})}),a(window).on(m.events.resize,function(){t._resize()},{ns:this.id})},_slideToSlide:function(e){var t,n,i,s=this.element,a=this.options;void 0!==this.slides[e]&&this.currentIndex!==e&&(i=e>this.currentIndex?"next":"prev",t=this.slides[this.currentIndex],n=this.slides[e],this.currentIndex=e,this._effect(t,n,a.effect,i),s.find(".carousel-bullet").removeClass("bullet-on").removeClass(a.clsBulletOn),s.find(".carousel-bullet:nth-child("+(this.currentIndex+1)+")").addClass("bullet-on").addClass(a.clsBulletOn))},_slideTo:function(e,t){var n,i,s=this.element,a=this.options;void 0===e&&(e="next"),n=this.slides[this.currentIndex],"next"===e?(this.currentIndex++,this.currentIndex>=this.slides.length&&(this.currentIndex=0)):(this.currentIndex--,this.currentIndex<0&&(this.currentIndex=this.slides.length-1)),i=this.slides[this.currentIndex],this._effect(n,i,a.effect,e,t),s.find(".carousel-bullet").removeClass("bullet-on").removeClass(a.clsBulletOn),s.find(".carousel-bullet:nth-child("+(this.currentIndex+1)+")").addClass("bullet-on").addClass(a.clsBulletOn)},_effect:function(e,t,n,i,s){var a,o,r,l,c,d=this,u=this.options,h=u.duration,p=u.effectFunc,f=u.period;void 0!==t.data("duration")&&(h=t.data("duration")),void 0!==t.data("effectFunc")&&(p=t.data("effectFunc")),"switch"===n&&(h=0),e.stop(!0),t.stop(!0),this.isAnimate=!0,setTimeout(function(){d.isAnimate=!1},h+100),a="slide"===n?"next"===i?"slideLeft":"slideRight":"slide-v"===n?"next"===i?"slideUp":"slideDown":n,v.includes(n)||(a="switch"),o=a,r=e,l=t,c={duration:h,ease:p},m.animations[o](r,l,c),e.removeClass("active-slide"),t.addClass("active-slide"),setTimeout(function(){d._fireEvent("slide-show",{current:t[0],prev:e[0]})},h),setTimeout(function(){d._fireEvent("slide-hide",{current:e[0],next:t[0]})},h),!0===s&&(void 0!==t.data("period")&&(f=t.data("period")),this.interval=setTimeout(function(){var e="left"===u.direction?"next":"prior";d._slideTo(e,!0)},f))},toSlide:function(e){this._slideToSlide(e)},next:function(){this._slideTo("next")},prev:function(){this._slideTo("prev")},stop:function(){clearInterval(this.interval),o.exec(this.options.onStop,[this.element]),this.element.fire("stop")},play:function(){this._start(),o.exec(this.options.onPlay,[this.element]),this.element.fire("play")},setEffect:function(e){var t=this.element,n=this.options,i=t.find(".slide");v.includes(e)&&(n.effect=e,i.removeStyleProperty("transform").css({top:0,left:0}))},changeAttribute:function(e,t){"data-effect"===e&&this.setEffect(t)},destroy:function(){var e=this.element,t=this.options;return e.off(m.events.click,".carousel-bullet"),e.off(m.events.click,".carousel-switch-next"),e.off(m.events.click,".carousel-switch-prev"),!0===t.stopOnMouse&&!0===t.autoStart&&(e.off(m.events.enter),e.off(m.events.leave)),!0===t.controlsOnMouse&&(e.off(m.events.enter),e.off(m.events.leave)),e.off(m.events.click,".slide"),a(window).off(m.events.resize,{ns:this.id}),e}})}(Metro,m4q),function(n,t){"use strict";var s=n.utils,i={charmsDeferred:0,position:"right",opacity:1,clsCharms:"",onCharmCreate:n.noop,onOpen:n.noop,onClose:n.noop,onToggle:n.noop};n.charmsSetup=function(e){i=t.extend({},i,e)},window.metroCharmsSetup,n.charmsSetup(window.metroCharmsSetup),n.Component("charms",{init:function(e,t){return this._super(t,e,i,{origin:{background:""}}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("charm-create",{element:e})},_createStructure:function(){var e=this.element,t=this.options;e.addClass("charms").addClass(t.position+"-side").addClass(t.clsCharms),this.origin.background=e.css("background-color"),e.css({backgroundColor:s.computedRgbToRgba(s.getStyleOne(e,"background-color"),t.opacity)})},_createEvents:function(){},open:function(){var e=this.element,t=this.options;e.addClass("open"),s.exec(t.onOpen,null,e[0]),e.fire("open")},close:function(){var e=this.element,t=this.options;e.removeClass("open"),s.exec(t.onClose,null,e[0]),e.fire("close")},toggle:function(){var e=this.element,t=this.options;!0===e.hasClass("open")?this.close():this.open(),s.exec(t.onToggle,null,e[0]),e.fire("toggle")},opacity:function(e){var t=this.element,n=this.options;if(void 0===e)return n.opacity;var i=Math.abs(parseFloat(e));i<0||1<i||(n.opacity=i,t.css({backgroundColor:s.computedRgbToRgba(s.getStyleOne(t,"background-color"),i)}))},changeOpacity:function(){var e=this.element;this.opacity(e.attr("data-opacity"))},changeAttribute:function(e){switch(e){case"data-opacity":this.changeOpacity()}},destroy:function(){return this.element}}),n.charms={check:function(e){return!1!==s.isMetroObject(e,"charms")||(console.warn("Element is not a charms component"),!1)},isOpen:function(e){if(!1!==this.check(e))return t(e).hasClass("open")},open:function(e){!1!==this.check(e)&&n.getPlugin(e,"charms").open()},close:function(e){!1!==this.check(e)&&n.getPlugin(e,"charms").close()},toggle:function(e){!1!==this.check(e)&&n.getPlugin(e,"charms").toggle()},closeAll:function(){t("[data-role*=charms]").each(function(){n.getPlugin(this,"charms").close()})},opacity:function(e,t){!1!==this.check(e)&&n.getPlugin(e,"charms").opacity(t)}}}(Metro,m4q),function(o,h){"use strict";var p=o.utils,r="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD//gA7Q1JFQVRPUjogZ2QtanBlZyB2MS4wICh1c2luZyBJSkcgSlBFRyB2NjIpLCBxdWFsaXR5ID0gOTAK/9sAQwADAgIDAgIDAwMDBAMDBAUIBQUEBAUKBwcGCAwKDAwLCgsLDQ4SEA0OEQ4LCxAWEBETFBUVFQwPFxgWFBgSFBUU/9sAQwEDBAQFBAUJBQUJFA0LDRQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU/8AAEQgAUABQAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm5+jp6vLz9PX29/j5+v/aAAwDAQACEQMRAD8A+t+KKPxo/GgA70Yo/Gj8aADFH4VesdC1HUl3WtjcXCf344yV/PGKW+0HUtNXddWNzbp/fkjIX88YoAofhR+FH40fjQAfhR+FH40fjQAUUUUAFepeAPh5D9li1LVYhK8g3Q27j5VXszDuT6f5HA+FtOXVvEWn2rjMcko3j1UckfkDX0MBgYHAoARVCKFUBVHAA6ClZQwKkZBGCDS0UAec+Pvh3BJay6lpUQimjBeW3QYVx3Kjsfbv/PyqvpuvnvxfpqaT4l1C1QbY0lJUDsrfMB+RoAyKKKKACiiigDa8GXq6f4p02eQgIJQpJ7Bvlz+tfQP4V8yDg17P4A8cw65ZxWV5IE1KMbfmP+uA7j39R+NAHaUfhSUUAL+FeA+OL1NQ8WalNGQU83YCO+0Bf6V6b498cQ6BZyWlrIJNSkXaApz5QP8AEff0FeKk5OTyTQAUUUUAH40fjRU1naTX93DbQIXmlYIijuTQBc0Dw/eeI74W1mm49XkbhUHqTXsHhz4eaXoCpI8YvbscmaYZAP8Asr0H8/etHwv4cg8M6XHaxANIfmllxy7dz9PStigA/Gk/GlooA5bxJ8PdL19XkWMWd43PnwjGT/tL0P8AP3rx/X/D954cvjbXibT1SReVceoNfRFZHijw5B4m0uS1lAWQfNFLjlG7H6etAHz5+NH41NeWk1hdzW06FJonKMp7EGoaACvQfhBowudTudRkXK2y7I8j+Nup/Afzrz6vafhRaCDwmkgHM8zufwO3/wBloA7Kiij8KACkpaSgBaSj8KKAPJvi/owttTttRjXC3K7JMf3l6H8R/KvPq9p+K1qJ/CbyEcwTI4P1O3/2avFqAP/Z",n={chatDeferred:0,inputTimeFormat:"%m-%d-%y",timeFormat:"%d %b %l:%M %p",name:"John Doe",avatar:r,welcome:null,title:null,width:"100%",height:"auto",randomColor:!1,messages:null,sendButtonTitle:"Send",readonly:!1,clsChat:"",clsName:"",clsTime:"",clsInput:"",clsSendButton:"",clsMessageLeft:"default",clsMessageRight:"default",onMessage:o.noop,onSend:o.noop,onSendButtonClick:o.noop,onChatCreate:o.noop};o.chatSetup=function(e){n=h.extend({},n,e)},window.metroChatSetup,o.chatSetup(window.metroChatSetup),o.Component("chat",{init:function(e,t){return this._super(t,e,n,{input:null,classes:"primary secondary success alert warning yellow info dark light".split(" "),lastMessage:null}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("chat-create",{element:e})},_createStructure:function(){var e,t,n=this,i=this.element,s=this.options,a=[{html:s.sendButtonTitle,cls:s.clsSendButton+" js-chat-send-button",onclick:s.onSendButtonClick}];i.addClass("chat").addClass(s.clsChat),i.css({width:s.width,height:s.height}),p.isValue(s.title)&&h("<div>").addClass("title").html(s.title).appendTo(i),h("<div>").addClass("messages").appendTo(i),e=h("<div>").addClass("message-input").appendTo(i),(t=h("<input type='text'>")).appendTo(e),t.input({customButtons:a,clsInput:s.clsInput}),s.welcome&&this.add({text:s.welcome,time:new Date,position:"left",name:"Welcome",avatar:r}),p.isValue(s.messages)&&"string"==typeof s.messages&&(s.messages=p.isObject(s.messages)),!p.isNull(s.messages)&&"object"==typeof s.messages&&0<p.objectLength(s.messages)&&h.each(s.messages,function(){n.add(this)}),i.find(".message-input")[s.readonly?"addClass":"removeClass"]("disabled")},_createEvents:function(){function t(){var e,t=""+a.val();if(""===t.trim())return!1;e={id:p.elementId(""),name:s.name,avatar:s.avatar,text:t,position:"right",time:new Date},n.add(e),p.exec(s.onSend,[e],i[0]),i.fire("send",{msg:e}),a.val("")}var n=this,i=this.element,s=this.options,e=i.find(".js-chat-send-button"),a=i.find("input[type=text]");e.on(o.events.click,function(){t()}),a.on(o.events.keyup,function(e){e.keyCode===o.keyCode.ENTER&&t()})},add:function(e){var t,n,i,s,a,o,r,l,c=this.element,d=this.options,u=c.find(".messages");return l="string"==typeof e.time?e.time.toDate(d.inputTimeFormat):e.time,n=h("<div>").addClass("message").addClass(e.position).appendTo(u),i=h("<div>").addClass("message-sender").addClass(d.clsName).html(e.name).appendTo(n),s=h("<div>").addClass("message-time").addClass(d.clsTime).html(l.format(d.timeFormat)).appendTo(n),a=h("<div>").addClass("message-item").appendTo(n),o=h("<img>").attr("src",e.avatar).addClass("message-avatar").appendTo(a),r=h("<div>").addClass("message-text").html(e.text).appendTo(a),p.isValue(e.id)&&n.attr("id",e.id),!0===d.randomColor?(t=h.random(0,this.classes.length-1),r.addClass(this.classes[t])):("left"===e.position&&p.isValue(d.clsMessageLeft)&&r.addClass(d.clsMessageLeft),"right"===e.position&&p.isValue(d.clsMessageRight)&&r.addClass(d.clsMessageRight)),p.exec(d.onMessage,[e,{message:n,sender:i,time:s,item:a,avatar:o,text:r}],n[0]),c.fire("message",{msg:e,el:{message:n,sender:i,time:s,item:a,avatar:o,text:r}}),setImmediate(function(){c.fire("onmessage",{message:e,element:n[0]})}),u.animate({draw:{scrollTop:u[0].scrollHeight},dur:1e3}),this.lastMessage=e,this},addMessages:function(e){var t=this;return p.isValue(e)&&"string"==typeof e&&(e=p.isObject(e)),"object"==typeof e&&0<p.objectLength(e)&&h.each(e,function(){t.add(this)}),this},delMessage:function(e){return this.element.find(".messages").find("#"+e).remove(),this},updMessage:function(e){var t=this.element.find(".messages").find("#"+e.id);return 0===t.length||(t.find(".message-text").html(e.text),t.find(".message-time").html(e.time)),this},clear:function(){this.element.find(".messages").html(""),this.lastMessage=null},toggleReadonly:function(e){var t=this.element,n=this.options;n.readonly=void 0===e?!n.readonly:e,t.find(".message-input")[n.readonly?"addClass":"removeClass"]("disabled")},changeAttribute:function(e){switch(e){case"data-readonly":this.toggleReadonly()}},destroy:function(){var e=this.element,t=e.find(".js-chat-send-button"),n=e.find("input[type=text]");return t.off(o.events.click),n.off(o.events.keyup),e}})}(Metro,m4q),function(e,a){"use strict";var o=e.utils,n={checkboxDeferred:0,transition:!0,style:1,caption:"",captionPosition:"right",indeterminate:!1,clsCheckbox:"",clsCheck:"",clsCaption:"",onCheckboxCreate:e.noop};e.checkboxSetup=function(e){n=a.extend({},n,e)},window.metroCheckboxSetup,e.checkboxSetup(window.metroCheckboxSetup),e.Component("checkbox",{init:function(e,t){return this._super(t,e,n,{origin:{className:""}}),this},_create:function(){this._createStructure(),this._createEvents(),this._fireEvent("checkbox-create",{element:this.element})},_createStructure:function(){var e,t=this.element,n=this.options,i=a("<span>").addClass("check"),s=a("<span>").addClass("caption").html(n.caption);t.attr("type","checkbox"),o.isValue(t.attr("id"))||t.attr("id",o.elementId("checkbox")),void 0!==t.attr("readonly")&&t.on("click",function(e){e.preventDefault()}),e=t.wrap("<label>").addClass("checkbox "+t[0].className).addClass(2===n.style?"style2":"").attr("for",t.attr("id")),i.appendTo(e),s.appendTo(e),!0===n.transition&&e.addClass("transition-on"),"left"===n.captionPosition&&e.addClass("caption-left"),this.origin.className=t[0].className,t[0].className="",e.addClass(n.clsCheckbox),s.addClass(n.clsCaption),i.addClass(n.clsCheck),n.indeterminate&&(t[0].indeterminate=!0),t.is(":disabled")?this.disable():this.enable()},_createEvents:function(){var e=this.element,t=e.siblings(".check");e.on("focus",function(){t.addClass("focused")}),e.on("blur",function(){t.removeClass("focused")})},indeterminate:function(e){o.isNull(e)&&(e=!0),this.element[0].indeterminate=e},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},changeAttribute:function(e){var t,n=this.element,i=this.options,s=n.parent();switch(e){case"disabled":this.toggleState();break;case"data-indeterminate":n[0].indeterminate=!0===JSON.parse(n.attr("data-indeterminate"));break;case"data-style":t=parseInt(n.attr("data-style")),o.isInt(t)&&(i.style=t,s.removeClass("style1 style2").addClass("style"+t))}},destroy:function(){var e=this.element;return e.off("focus"),e.off("blur"),e}})}(Metro,m4q),function(e,t){"use strict";var n={clockDeferred:0,showTime:!0,showDate:!0,timeFormat:"24",dateFormat:"american",divider:"&nbsp;&nbsp;",leadingZero:!0,dateDivider:"-",timeDivider:":",onTick:e.noop,onSecond:e.noop,onClockCreate:e.noop};e.clockSetup=function(e){n=t.extend({},n,e)},window.metroClockSetup,e.clockSetup(window.metroClockSetup),e.Component("clock",{init:function(e,t){return this._super(t,e,n,{_clockInterval:null}),this},_create:function(){var e=this,t=this.element;this._fireEvent("clock-create",{element:t}),this._tick(),this._clockInterval=setInterval(function(){e._tick()},500),this._secondInterval=setInterval(function(){e._second()},1e3)},_addLeadingZero:function(e){return e<10&&(e="0"+e),e},_second:function(){var e=new Date;this._fireEvent("second",{timestamp:e})},_tick:function(){var e=this.element,t=this.options,n=new Date,i="",s=n.getHours(),a=n.getMinutes(),o=n.getSeconds(),r=n.getDate(),l=n.getMonth()+1,c=n.getFullYear(),d="";12===parseInt(t.timeFormat)&&(d=" AM",11<s&&(d=" PM"),12<s&&(s-=12),0===s&&(s=12)),a=this._addLeadingZero(a),o=this._addLeadingZero(o),t.leadingZero&&(s=this._addLeadingZero(s),l=this._addLeadingZero(l),r=this._addLeadingZero(r)),t.showDate&&("american"===t.dateFormat?(i+="<span class='date-month'>"+l+"</span>",i+="<span class='date-divider'>"+t.dateDivider+"</span>",i+="<span class='date-day'>"+r+"</span>"):(i+="<span class='date-day'>"+r+"</span>",i+="<span class='date-divider'>"+t.dateDivider+"</span>",i+="<span class='date-month'>"+l+"</span>"),i+="<span class='date-divider'>"+t.dateDivider+"</span>",i+="<span class='date-year'>"+c+"</span>",i+=t.divider),t.showTime&&(i+="<span class='clock-hour'>"+s+"</span>",i+="<span class='clock-divider'>"+t.timeDivider+"</span>",i+="<span class='clock-minute'>"+a+"</span>",i+="<span class='clock-divider'>"+t.timeDivider+"</span>",i+="<span class='clock-second'>"+o+"</span>",i+="<span class='clock-suffix'>"+d+"</span>"),e.html(i),this._fireEvent("tick",{timestamp:n})},changeAttribute:function(e){},destroy:function(){return clearInterval(this._clockInterval),this._clockInterval=null,this.element}})}(Metro,m4q),function(o,r){"use strict";var l=o.utils,n={collapseDeferred:0,collapsed:!1,toggleElement:!1,duration:100,onExpand:o.noop,onCollapse:o.noop,onCollapseCreate:o.noop};o.collapseSetup=function(e){n=r.extend({},n,e)},window.metroCollapseSetup,o.collapseSetup(window.metroCollapseSetup),o.Component("collapse",{init:function(e,t){return this._super(t,e,n,{toggle:null}),this},_create:function(){var e,t=this,n=this.element,i=this.options;e=!1!==i.toggleElement?r(i.toggleElement):0<n.siblings(".collapse-toggle").length?n.siblings(".collapse-toggle"):n.siblings("a:nth-child(1)"),!0!==i.collapsed&&!0!==n.attr("collapsed")||n.hide(0),e.on(o.events.click,function(e){"block"!==n.css("display")||n.hasClass("keep-open")?t._open(n):t._close(n),-1===["INPUT"].indexOf(e.target.tagName)&&e.preventDefault(),e.stopPropagation()}),this.toggle=e,this._fireEvent("collapse-create",{element:n})},_close:function(e,t){var n=r(e),i=o.getPlugin(n[0],"collapse").options,s=t?"show":"slideUp",a=t?0:i.duration;this.toggle.removeClass("active-toggle"),n[s](a,function(){e.trigger("onCollapse",null,e),e.data("collapsed",!0),e.addClass("collapsed"),l.exec(i.onCollapse,null,n[0]),n.fire("collapse")})},_open:function(e,t){var n=r(e),i=o.getPlugin(n[0],"collapse").options,s=t?"show":"slideDown",a=t?0:i.duration;this.toggle.addClass("active-toggle"),n[s](a,function(){e.trigger("onExpand",null,e),e.data("collapsed",!1),e.removeClass("collapsed"),l.exec(i.onExpand,null,n[0]),n.fire("expand")})},collapse:function(e){this._close(this.element,e)},expand:function(e){this._open(this.element,e)},close:function(e){this._close(this.element,e)},open:function(e){this._open(this.element,e)},isCollapsed:function(){return this.element.data("collapsed")},toggleState:function(){var e=this.element;!0===e.attr("collapsed")||!0===e.data("collapsed")?this.collapse():this.expand()},changeAttribute:function(e){switch(e){case"collapsed":case"data-collapsed":this.toggleState()}},destroy:function(){return this.toggle.off(o.events.click),this.element}})}(Metro,m4q),function(a,o){"use strict";var r=a.utils,i={name:"cookies_accepted",template:null,templateSource:null,acceptButton:".cookie-accept-button",cancelButton:".cookie-cancel-button",message:"Our website uses cookies to monitor traffic on our website and ensure that we can provide our customers with the best online experience possible.",duration:"30days",clsContainer:"",clsMessage:"",clsButtons:"",clsAcceptButton:"alert",clsCancelButton:"",onAccept:a.noop,onDecline:a.noop};a.cookieDisclaimer={init:function(e){var t=this,n=a.cookie;this.options=o.extend({},i,e),this.disclaimer=o("<div>"),n.getCookie(this.options.name)||(this.options.template?o.get(this.options.template).then(function(e){t.create(e)}):this.options.templateSource?this.create(o(this.options.templateSource)):this.create())},create:function(e){var t,n=a.cookie,i=this.options,s=this.disclaimer;s.addClass("cookie-disclaimer-block").addClass(i.clsContainer),e?e instanceof o?s.append(e):s.html(e):(t=o("<div>").addClass("cookie-disclaimer-actions").addClass(i.clsButtons).append(o("<button>").addClass("button cookie-accept-button").addClass(i.clsAcceptButton).html("Accept")).append(o("<button>").addClass("button cookie-cancel-button").addClass(i.clsCancelButton).html("Cancel")),s.html(o("<div>").addClass(i.clsMessage).html(i.message)).append(o("<hr>").addClass("thin")).append(t)),s.appendTo(o("body")),s.on(a.events.click,i.acceptButton,function(){var t=0,e=(""+i.duration).toArray(" ");o.each(e,function(){var e=""+this;e.includes("day")?t+=24*parseInt(e)*60*60*1e3:e.includes("hour")?t+=60*parseInt(e)*60*1e3:e.includes("min")?t+=60*parseInt(e)*1e3:e.includes("sec")?t+=1e3*parseInt(e):t+=parseInt(e)}),n.setCookie(i.name,!0,t),r.exec(i.onAccept),s.remove()}),s.on(a.events.click,i.cancelButton,function(){r.exec(i.onDecline),s.remove()})}}}(Metro,m4q),function(e,l){"use strict";var c={path:"/",expires:null,maxAge:null,domain:null,secure:!1,samesite:null};e.cookieSetup=function(e){c=l.extend({},c,e)},window.metroCookieSetup,e.cookieSetup(window.metroCookieSetup),e.cookie={getCookies:function(){var e=document.cookie.toArray(";"),t={};return l.each(e,function(){var e=this.split("=");t[e[0]]=e[1]}),t},getCookie:function(e){var t,n,i=encodeURIComponent(e)+"=",s=document.cookie.toArray(";");for(t=0;t<s.length;t++){for(n=s[t];" "===n.charAt(0);)n=n.substring(1,n.length);if(0===n.indexOf(i))return decodeURIComponent(n.substring(i.length,n.length))}return null},setCookie:function(e,t,n){var i,s,a=encodeURIComponent(e),o=encodeURIComponent(t),r=[];s=n&&"object"!=typeof n?((i=new Date).setTime(i.getTime()+parseInt(n)),l.extend({},c,{expires:i.toUTCString()})):l.extend({},c,n),l.each(s,function(e,t){"secure"!==e&&t&&r.push(l.dashedName(e)+"="+t),"secure"===e&&!0===t&&r.push("secure")}),document.cookie=a+"="+o+"; "+r.join("; ")},delCookie:function(e){this.setCookie(e,!1,{maxAge:-1})}}}(Metro,m4q),function(s,C){"use strict";var h=s.utils,n={countdownDeferred:0,stopOnBlur:!0,animate:"none",animationFunc:"linear",inputFormat:null,locale:METRO_LOCALE,days:0,hours:0,minutes:0,seconds:0,date:null,start:!0,clsCountdown:"",clsPart:"",clsZero:"",clsAlarm:"",clsDays:"",clsHours:"",clsMinutes:"",clsSeconds:"",onAlarm:s.noop,onTick:s.noop,onZero:s.noop,onBlink:s.noop,onCountdownCreate:s.noop};s.countdownSetup=function(e){n=C.extend({},n,e)},window.metroCountdownSetup,s.countdownSetup(window.metroCountdownSetup),s.Component("countdown",{init:function(e,t){return this._super(t,e,n,{locale:s.locales["en-US"],breakpoint:(new Date).getTime(),blinkInterval:null,tickInterval:null,zeroDaysFired:!1,zeroHoursFired:!1,zeroMinutesFired:!1,zeroSecondsFired:!1,fontSize:parseInt(h.getStyleOne(t,"font-size")),current:{d:0,h:0,m:0,s:0},inactiveTab:!1,id:h.elementId("countdown")}),this},_create:function(){var e=this.options;this.locale=void 0!==s.locales[e.locale]?s.locales[e.locale]:s.locales["en-US"],this._build(),this._createEvents()},_setBreakpoint:function(){var e=this.options;this.breakpoint=(new Date).getTime(),h.isValue(e.date)&&h.isDate(e.date,e.inputFormat)&&(this.breakpoint=h.isValue(e.inputFormat)?e.date.toDate(e.inputFormat).getTime():new Date(e.date).getTime()),0<parseInt(e.days)&&(this.breakpoint+=864e5*parseInt(e.days)),0<parseInt(e.hours)&&(this.breakpoint+=36e5*parseInt(e.hours)),0<parseInt(e.minutes)&&(this.breakpoint+=6e4*parseInt(e.minutes)),0<parseInt(e.seconds)&&(this.breakpoint+=1e3*parseInt(e.seconds))},_build:function(){var n,e,i=this,s=this.element,a=this.options,t=(new Date).getTime();s.attr("id")||s.attr("id",h.elementId("countdown")),h.isValue(s.attr("id"))||s.attr("id",h.elementId("countdown")),s.addClass("countdown").addClass(a.clsCountdown),this._setBreakpoint(),n=Math.round((i.breakpoint-t)/864e5),C.each(["days","hours","minutes","seconds"],function(){var e=C("<div>").addClass("part "+this).addClass(a.clsPart).attr("data-label",i.locale.calendar.time[this]).appendTo(s);if("days"===this&&e.addClass(a.clsDays),"hours"===this&&e.addClass(a.clsHours),"minutes"===this&&e.addClass(a.clsMinutes),"seconds"===this&&e.addClass(a.clsSeconds),C("<div>").addClass("digit").appendTo(e),C("<div>").addClass("digit").appendTo(e),"days"===this&&100<=n)for(var t=0;t<String(Math.round(n/100)).length;t++)C("<div>").addClass("digit").appendTo(e)}),(e=s.find(".digit")).append(C("<span class='digit-placeholder'>").html("0")),e.append(C("<span class='digit-value'>").html("0")),this._fireEvent("countdown-create",{element:s}),!0===a.start?this.start():this.tick()},_createEvents:function(){var e=this;C(document).on("visibilitychange",function(){document.hidden?e.pause():e.resume()},{ns:this.id})},blink:function(){var e=this.element,t=this.options;e.toggleClass("blink"),h.exec(t.onBlink,[this.current],e[0]),e.fire("blink",{time:this.current})},tick:function(){var e,t,n,i,s,a=this.element,o=this.options,r=(new Date).getTime(),l=a.find(".days"),c=a.find(".hours"),d=a.find(".minutes"),u=a.find(".seconds");if((e=Math.floor((this.breakpoint-r)/1e3))<=-1)return this.stop(),a.addClass(o.clsAlarm),h.exec(o.onAlarm,[r],a[0]),void a.fire("alarm",{time:r});e-=86400*(t=Math.floor(e/86400)),this.current.d!==t&&(this.current.d=t,this.draw("days",t)),0===t&&!1===this.zeroDaysFired&&(this.zeroDaysFired=!0,l.addClass(o.clsZero),h.exec(o.onZero,["days",l],a[0]),a.fire("zero",{parts:["days",l]})),e-=3600*(n=Math.floor(e/3600)),this.current.h!==n&&(this.current.h=n,this.draw("hours",n)),0===t&&0===n&&!1===this.zeroHoursFired&&(this.zeroHoursFired=!0,c.addClass(o.clsZero),h.exec(o.onZero,["hours",c],a[0]),a.fire("zero",{parts:["hours",c]})),e-=60*(i=Math.floor(e/60)),this.current.m!==i&&(this.current.m=i,this.draw("minutes",i)),0===t&&0===n&&0===i&&!1===this.zeroMinutesFired&&(this.zeroMinutesFired=!0,d.addClass(o.clsZero),h.exec(o.onZero,["minutes",d],a[0]),a.fire("zero",{parts:["minutes",d]})),s=Math.floor(e/1),this.current.s!==s&&(this.current.s=s,this.draw("seconds",s)),0===t&&0===n&&0===i&&0===s&&!1===this.zeroSecondsFired&&(this.zeroSecondsFired=!0,u.addClass(o.clsZero),h.exec(o.onZero,["seconds",u],a[0]),a.fire("zero",{parts:["seconds",u]})),h.exec(o.onTick,[{days:t,hours:n,minutes:i,seconds:s}],a[0]),a.fire("tick",{days:t,hours:n,minutes:i,seconds:s})},draw:function(e,t){var n,i,s,a,o,r,l,c,d,u,h,p,f,m,v,g=this.element,w=this.options;for(1===(t=""+t).length&&(t="0"+t),o=t.length,i=(n=g.find("."+e+" .digit:not(-old-digit)")).length,r=0;r<o;r++)if(a=n.eq(i-1).find(".digit-value"),s=Math.floor(parseInt(t)/Math.pow(10,r))%10,parseInt(a.text())!==s){switch((""+w.animate).toLowerCase()){case"slide":m=void 0,v=(f=a).height(),f.siblings("-old-digit").remove(),(m=f.clone().appendTo(f.parent())).css({top:-1*v+"px"}),f.addClass("-old-digit").animate({draw:{top:v,opacity:0},dur:900,ease:w.animationFunc,onDone:function(){C(this).remove()}}),m.html(s).animate({draw:{top:0,opacity:1},dur:900,ease:w.animationFunc});break;case"fade":p=void 0,(h=a).siblings("-old-digit").remove(),(p=h.clone().appendTo(h.parent())).css({opacity:0}),h.addClass("-old-digit").animate({draw:{opacity:0},dur:450,ease:w.animationFunc,onDone:function(){C(this).remove()}}),p.html(s).animate({draw:{opacity:1},dur:900,ease:w.animationFunc});break;case"zoom":c=void 0,d=(l=a).height(),u=parseInt(l.style("font-size")),l.siblings("-old-digit").remove(),(c=l.clone().appendTo(l.parent())).css({top:0,left:0,opacity:1}),l.addClass("-old-digit").animate({draw:{top:d,opacity:0,fontSize:0},dur:900,ease:w.animationFunc,onDone:function(){C(this).remove()}}),c.html(s).animate({draw:{top:0,opacity:1,fontSize:[0,u]},dur:900,ease:w.animationFunc});break;default:a.html(s)}i--}},start:function(){var e=this,t=this.element;!1!==t.data("paused")&&(clearInterval(this.blinkInterval),clearInterval(this.tickInterval),t.data("paused",!1),this._setBreakpoint(),this.tick(),this.blinkInterval=setInterval(function(){e.blink()},500),this.tickInterval=setInterval(function(){e.tick()},1e3))},stop:function(){var e=this.element;clearInterval(this.blinkInterval),clearInterval(this.tickInterval),e.data("paused",!0),e.find(".digit").html("0"),this.current={d:0,h:0,m:0,s:0}},pause:function(){clearInterval(this.blinkInterval),clearInterval(this.tickInterval),this.element.data("paused",!0)},resume:function(){var e=this;this.element.data("paused",!1),this.blinkInterval=setInterval(function(){e.blink()},500),this.tickInterval=setInterval(function(){e.tick()},1e3)},reset:function(){var e=this,t=this.element,n=this.options;clearInterval(this.blinkInterval),clearInterval(this.tickInterval),t.find(".part").removeClass(n.clsZero),t.find(".digit").html("0"),this._setBreakpoint(),t.data("paused",!1),this.tick(),this.blinkInterval=setInterval(function(){e.blink()},500),this.tickInterval=setInterval(function(){e.tick()},1e3)},togglePlay:function(){!0===this.element.attr("data-pause")?this.pause():this.start()},isPaused:function(){return this.element.data("paused")},getBreakpoint:function(e){return!0===e?new Date(this.breakpoint):this.breakpoint},getLeft:function(){var e=(new Date).getTime(),t=Math.floor(this.breakpoint-e);return{days:Math.round(t/864e5),hours:Math.round(t/36e5),minutes:Math.round(t/6e4),seconds:Math.round(t/1e3)}},i18n:function(e){var t=this,n=this.element,i=this.options;return void 0===e?i.locale:void 0!==s.locales[e]&&(i.locale=e,this.locale=s.locales[i.locale],void C.each(["days","hours","minutes","seconds"],function(){var e=".part."+this;n.find(e).attr("data-label",t.locale.calendar.time[this])}))},changeAttrLocale:function(){var e=this.element.attr("data-locale");this.i18n(e)},changeAttribute:function(e){switch(e){case"data-pause":this.togglePlay();break;case"data-locale":this.changeAttrLocale()}},destroy:function(){return clearInterval(this.blinkInterval),clearInterval(this.tickInterval),C(document).off("visibilitychange",{ns:this.id}),this.element}})}(Metro,m4q),function(e,i){"use strict";var a=e.utils,n={startOnViewport:!0,counterDeferred:0,duration:2e3,value:0,from:0,timeout:0,delimiter:",",prefix:"",suffix:"",onStart:e.noop,onStop:e.noop,onTick:e.noop,onCounterCreate:e.noop};e.counterSetup=function(e){n=i.extend({},n,e)},window.metroCounterSetup,e.counterSetup(window.metroCounterSetup),e.Component("counter",{init:function(e,t){return this._super(t,e,n,{numbers:[],html:i(t).html(),started:!1,id:a.elementId("counter")}),this},_create:function(){this._createEvents(),this._fireEvent("counter-create"),this._run()},_createEvents:function(){var e=this,t=this.element,n=this.options;i.window().on("scroll",function(){!0===n.startOnViewport&&a.inViewport(t[0])&&!e.started&&e.start()},{ns:this.id})},_run:function(){var e=this.element,t=this.options;!(this.started=!1)!==t.startOnViewport?this.start():a.inViewport(e[0])&&this.start()},startInViewport:function(e,t){var n=this.options;a.isValue(t)&&(n.from=+t),a.isValue(e)&&(n.value=+e),this._run()},start:function(e,t){var n=this,i=this.element,s=this.options;a.isValue(t)&&(s.from=+t),a.isValue(e)&&(s.value=+e),this.started=!0,this._fireEvent("start"),i.animate({draw:{innerHTML:[s.from,s.value]},defer:s.timeout,dur:s.duration,onFrame:function(){n._fireEvent("tick",{value:+this.innerHTML}),this.innerHTML=s.prefix+Number(this.innerHTML).format(0,0,s.delimiter)+s.suffix},onDone:function(){n._fireEvent("stop")}})},reset:function(){this.started=!1,this.element.html(this.html)},changeAttribute:function(e,t){var n=this.options;"data-value"===e&&(n.value=+t),"data-from"===e&&(n.from=+t)},destroy:function(){return i.window().off("scroll",{ns:this.id}),this.element}})}(Metro,m4q),function(l,c){"use strict";var d=l.utils,n={cubeDeferred:0,rules:null,color:null,flashColor:null,flashInterval:1e3,numbers:!1,offBefore:!0,attenuation:.3,stopOnBlur:!1,cells:4,margin:8,showAxis:!1,axisStyle:"arrow",cellClick:!1,autoRestart:5e3,clsCube:"",clsCell:"",clsSide:"",clsSideLeft:"",clsSideRight:"",clsSideTop:"",clsSideLeftCell:"",clsSideRightCell:"",clsSideTopCell:"",clsAxis:"",clsAxisX:"",clsAxisY:"",clsAxisZ:"",custom:l.noop,onTick:l.noop,onCubeCreate:l.noop};l.cubeSetup=function(e){n=c.extend({},n,e)},window.metroCubeSetup,l.cubeSetup(window.metroCubeSetup),l.cubeDefaultRules=[{on:{top:[16],left:[4],right:[1]},off:{top:[13,4],left:[1,16],right:[13,4]}},{on:{top:[12,15],left:[3,8],right:[2,5]},off:{top:[9,6,3],left:[5,10,15],right:[14,11,8]}},{on:{top:[11],left:[7],right:[6]},off:{top:[1,2,5],left:[9,13,14],right:[15,12,16]}},{on:{top:[8,14],left:[2,12],right:[9,3]},off:{top:[16],left:[4],right:[1]}},{on:{top:[10,7],left:[6,11],right:[10,7]},off:{top:[12,15],left:[3,8],right:[2,5]}},{on:{top:[13,4],left:[1,16],right:[13,4]},off:{top:[11],left:[7],right:[6]}},{on:{top:[9,6,3],left:[5,10,15],right:[14,11,8]},off:{top:[8,14],left:[2,12],right:[9,3]}},{on:{top:[1,2,5],left:[9,13,14],right:[15,12,16]},off:{top:[10,7],left:[6,11],right:[10,7]}}],l.Component("cube",{init:function(e,t){return this._super(t,e,n,{id:d.elementId("cube"),rules:null,interval:!1,ruleInterval:!1,running:!1,intervals:[]}),this},_create:function(){var e=this.element,t=this.options;null===t.rules?this.rules=l.cubeDefaultRules:this._parseRules(t.rules),this._createCube(),this._createEvents(),this._fireEvent("cube-create",{element:e})},_parseRules:function(e){if(null==e)return!1;if(d.isObject(e))return this.rules=d.isObject(e),!0;try{return this.rules=JSON.parse(e),!0}catch(e){return console.warn("Unknown or empty rules for cell flashing!"),!1}},_createCube:function(){var i=this.element,s=this.options,e=d.elementId("cube"),a=Math.pow(s.cells,2);i.addClass("cube").addClass(s.clsCube),i.attr("id")||i.attr("id",e),this.id=i.attr("id"),this._createCssForFlashColor(),this._createCssForCellSize(),c.each(["left","right","top"],function(){var e,t,n;for(e=c("<div>").addClass("side "+this+"-side").addClass(s.clsSide).appendTo(i),"left"===this&&e.addClass(s.clsSideLeft),"right"===this&&e.addClass(s.clsSideRight),"top"===this&&e.addClass(s.clsSideTop),n=0;n<a;n++)(t=c("<div>").addClass("cube-cell").addClass("cell-id-"+(n+1)).addClass(s.clsCell)).data("id",n+1).data("side",this),t.appendTo(e),!0===s.numbers&&t.html(n+1)});var t=i.find(".cube-cell");null!==s.color&&(d.isColor(s.color)?t.css({backgroundColor:s.color,borderColor:s.color}):t.addClass(s.color));c.each(["x","y","z"],function(){var e=c("<div>").addClass("axis "+s.axisStyle).addClass("axis-"+this).addClass(s.clsAxis);"x"===this&&e.addClass(s.clsAxisX),"y"===this&&e.addClass(s.clsAxisY),"z"===this&&e.addClass(s.clsAxisZ),e.appendTo(i)}),!1===s.showAxis&&i.find(".axis").hide(),this._run()},_run:function(){var e=this,t=this.element,n=this.options,i=0;clearInterval(this.interval),t.find(".cube-cell").removeClass("light"),n.custom!==l.noop?d.exec(n.custom,[t]):(t.find(".cube-cell").removeClass("light"),e._start(),i=d.isObject(this.rules)?d.objectLength(this.rules):0,this.interval=setInterval(function(){e._start()},i*n.flashInterval))},_createCssForCellSize:function(){var e,t,n=this.element,i=this.options,s=l.sheet;8===i.margin&&4===i.cells||(e=parseInt(d.getStyleOne(n,"width")),t=Math.ceil((e/2-i.margin*i.cells*2)/i.cells),d.addCssRule(s,"#"+n.attr("id")+" .side .cube-cell","width: "+t+"px!important; height: "+t+"px!important; margin: "+i.margin+"px!important;"))},_createCssForFlashColor:function(){var e,t,n,i=this.element,s=this.options,a=l.sheet,o=[],r=[];if(null!==s.flashColor){for(e="0 0 10px "+d.hexColorToRgbA(s.flashColor,1),t="0 0 10px "+d.hexColorToRgbA(s.flashColor,s.attenuation),n=0;n<3;n++)o.push(e),r.push(t);d.addCssRule(a,"@keyframes pulsar-cell-"+i.attr("id"),"0%, 100% { box-shadow: "+o.join(",")+"} 50% { box-shadow: "+r.join(",")+" }"),d.addCssRule(a,"#"+i.attr("id")+" .side .cube-cell.light","animation: pulsar-cell-"+i.attr("id")+" 2.5s 0s ease-out infinite; background-color: "+s.flashColor+"!important; border-color: "+s.flashColor+"!important;")}},_createEvents:function(){var e=this,t=this.element,n=this.options;c(window).on(l.events.blur,function(){!0===n.stopOnBlur&&!0===e.running&&e._stop()},{ns:t.attr("id")}),c(window).on(l.events.focus,function(){!0===n.stopOnBlur&&!1===e.running&&e._start()},{ns:t.attr("id")}),t.on(l.events.click,".cube-cell",function(){!0===n.cellClick&&c(this).toggleClass("light")})},_start:function(){var n=this;this.element.find(".cube-cell").removeClass("light"),this.running=!0,c.each(this.rules,function(e,t){n._execRule(e,t)})},_stop:function(){this.running=!1,clearInterval(this.interval),c.each(this.intervals,function(){clearInterval(this)})},_tick:function(e,t){var n=this,i=this.element,s=this.options;void 0===t&&(t=s.flashInterval*e);var a=setTimeout(function(){d.exec(s.onTick,[e],i[0]),i.fire("tick",{index:e}),clearInterval(a),d.arrayDelete(n.intervals,a)},t);this.intervals.push(a)},_toggle:function(e,t,n,i){var s=this;void 0===i&&(i=this.options.flashInterval*n);var a=setTimeout(function(){e["on"===t?"addClass":"removeClass"]("light"),clearInterval(a),d.arrayDelete(s.intervals,a)},i);this.intervals.push(a)},start:function(){this._start()},stop:function(){this._stop()},toRule:function(e,t){var n=this,i=this.element,s=this.options,a=this.rules;if(null!=a&&void 0!==a[e]){clearInterval(this.ruleInterval),this.ruleInterval=!1,this.stop(),i.find(".cube-cell").removeClass("light");for(var o=0;o<=e;o++)this._execRule(o,a[o],t);d.isInt(s.autoRestart)&&0<s.autoRestart&&(this.ruleInterval=setTimeout(function(){n._run()},s.autoRestart))}},_execRule:function(i,s,a){var o=this,r=this.element;this._tick(i,a),c.each(["left","right","top"],function(){var t="."+this+"-side",e=void 0!==s.on&&void 0!==s.on[this]&&s.on[this],n=void 0!==s.off&&void 0!==s.off[this]&&s.off[this];!1!==e&&c.each(e,function(){var e=r.find(t+" .cell-id-"+this);o._toggle(e,"on",i,a)}),!1!==n&&c.each(n,function(){var e=r.find(t+" .cell-id-"+this);o._toggle(e,"off",i,a)})})},rule:function(e){if(void 0===e)return this.rules;!0===this._parseRules(e)&&(this.options.rules=e,this.stop(),this.element.find(".cube-cell").removeClass("light"),this._run())},axis:function(e){var t=!0===e?"show":"hide";this.element.find(".axis")[t]()},changeRules:function(){var e=this.element,t=this.options,n=e.attr("data-rules");!0===this._parseRules(n)&&(this.stop(),e.find(".cube-cell").removeClass("light"),t.rules=n,this._run())},changeAxisVisibility:function(){var e=this.element,t=!0===JSON.parse(e.attr("data-show-axis"))?"show":"hide";e.find(".axis")[t]()},changeAxisStyle:function(){var e=this.element,t=e.attr("data-axis-style");e.find(".axis").removeClass("arrow line no-style").addClass(t)},changeAttribute:function(e){switch(e){case"data-rules":this.changeRules();break;case"data-show-axis":this.changeAxisVisibility();break;case"data-axis-style":this.changeAxisStyle()}},destroy:function(){var e=this.element;return clearInterval(this.interval),this.interval=null,c(window).off(l.events.blur,{ns:e.attr("id")}),c(window).off(l.events.focus,{ns:e.attr("id")}),e.off(l.events.click,".cube-cell"),e}})}(Metro,m4q),function(o,m){"use strict";var v=o.utils,n={datepickerDeferred:0,gmt:0,format:"%Y-%m-%d",inputFormat:null,locale:METRO_LOCALE,value:null,distance:3,month:!0,day:!0,year:!0,minYear:null,maxYear:null,scrollSpeed:4,copyInlineStyles:!1,clsPicker:"",clsPart:"",clsMonth:"",clsDay:"",clsYear:"",okButtonIcon:"<span class='default-icon-check'></span>",cancelButtonIcon:"<span class='default-icon-cross'></span>",onSet:o.noop,onOpen:o.noop,onClose:o.noop,onScroll:o.noop,onDatePickerCreate:o.noop};o.datePickerSetup=function(e){n=m.extend({},n,e)},window.metroDatePickerSetup,o.datePickerSetup(window.metroDatePickerSetup),o.Component("date-picker",{init:function(e,t){return this._super(t,e,n,{picker:null,isOpen:!1,value:new Date,locale:null,offset:(new Date).getTimezoneOffset()/60+1,listTimer:{day:null,month:null,year:null}}),this},_create:function(){var e=this.element,t=this.options;t.distance<1&&(t.distance=1),v.isValue(e.val())&&(t.value=e.val()),v.isValue(t.value)&&(v.isValue(t.inputFormat)?this.value=(""+t.value).toDate(t.inputFormat):v.isDate(t.value)&&(this.value=new Date(t.value))),void 0===o.locales[t.locale]&&(t.locale=METRO_LOCALE),this.locale=o.locales[t.locale].calendar,null===t.minYear&&(t.minYear=(new Date).getFullYear()-100),null===t.maxYear&&(t.maxYear=(new Date).getFullYear()+100),this._createStructure(),this._createEvents(),this._set(),this._fireEvent("datepicker-create",{element:e})},_createStructure:function(){var e,t,n,i,s,a,o,r,l,c,d=this.element,u=this.options,h=d.prev(),p=d.parent(),f=v.elementId("datepicker");if(e=m("<div>").attr("id",f).addClass("wheel-picker date-picker "+d[0].className).addClass(u.clsPicker),0===h.length?p.prepend(e):e.insertAfter(h),d.appendTo(e),o=m("<div>").addClass("date-wrapper").appendTo(e),!0===u.month&&(t=m("<div>").addClass("month").addClass(u.clsPart).addClass(u.clsMonth).appendTo(o)),!0===u.day&&(n=m("<div>").addClass("day").addClass(u.clsPart).addClass(u.clsDay).appendTo(o)),!0===u.year&&(i=m("<div>").addClass("year").addClass(u.clsPart).addClass(u.clsYear).appendTo(o)),r=m("<div>").addClass("select-wrapper").appendTo(e),l=m("<div>").addClass("select-block").appendTo(r),!0===u.month){for(t=m("<ul>").addClass("sel-month").appendTo(l),s=0;s<u.distance;s++)m("<li>").html("&nbsp;").data("value",-1).appendTo(t);for(s=0;s<12;s++)m("<li>").addClass("js-month-"+s+" js-month-real-"+this.locale.months[s].toLowerCase()).html(this.locale.months[s]).data("value",s).appendTo(t);for(s=0;s<u.distance;s++)m("<li>").html("&nbsp;").data("value",-1).appendTo(t)}if(!0===u.day){for(n=m("<ul>").addClass("sel-day").appendTo(l),s=0;s<u.distance;s++)m("<li>").html("&nbsp;").data("value",-1).appendTo(n);for(s=0;s<31;s++)m("<li>").addClass("js-day-"+s+" js-day-real-"+(s+1)).html(s+1).data("value",s+1).appendTo(n);for(s=0;s<u.distance;s++)m("<li>").html("&nbsp;").data("value",-1).appendTo(n)}if(!0===u.year){for(i=m("<ul>").addClass("sel-year").appendTo(l),s=0;s<u.distance;s++)m("<li>").html("&nbsp;").data("value",-1).appendTo(i);for(s=u.minYear,a=0;s<=u.maxYear;s++,a++)m("<li>").addClass("js-year-"+a+" js-year-real-"+s).html(s).data("value",s).appendTo(i);for(s=0;s<u.distance;s++)m("<li>").html("&nbsp;").data("value",-1).appendTo(i)}if(l.height(40*(2*u.distance+1)),c=m("<div>").addClass("action-block").appendTo(r),m("<button>").attr("type","button").addClass("button action-ok").html(u.okButtonIcon).appendTo(c),m("<button>").attr("type","button").addClass("button action-cancel").html(u.cancelButtonIcon).appendTo(c),!(d[0].className="")===u.copyInlineStyles)for(s=0;s<d[0].style.length;s++)e.css(d[0].style[s],d.css(d[0].style[s]));this.picker=e},_createEvents:function(){var r=this,a=this.options,l=this.picker;l.on(o.events.start,".select-block ul",function(e){if(!e.changedTouches){var t=this,n=v.pageXY(e).y;m(document).on(o.events.move,function(e){t.scrollTop-=a.scrollSpeed*(n>v.pageXY(e).y?-1:1),n=v.pageXY(e).y},{ns:l.attr("id")}),m(document).on(o.events.stop,function(){m(document).off(o.events.move,{ns:l.attr("id")}),m(document).off(o.events.stop,{ns:l.attr("id")})},{ns:l.attr("id")})}}),l.on(o.events.click,function(e){!1===r.isOpen&&r.open(),e.stopPropagation()}),l.on(o.events.click,".action-ok",function(e){var t,n,i,s=l.find(".sel-month li.active"),a=l.find(".sel-day li.active"),o=l.find(".sel-year li.active");t=0===s.length?r.value.getMonth():s.data("value"),n=0===a.length?r.value.getDate():a.data("value"),i=0===o.length?r.value.getFullYear():o.data("value"),r.value=new Date(i,t,n),r._correct(),r._set(),r.close(),e.stopPropagation()}),l.on(o.events.click,".action-cancel",function(e){r.close(),e.stopPropagation()});m.each(["month","day","year"],function(){var i=this,s=l.find(".sel-"+i);s.on("scroll",function(){r.isOpen&&(r.listTimer[i]&&(clearTimeout(r.listTimer[i]),r.listTimer[i]=null),r.listTimer[i]||(r.listTimer[i]=setTimeout(function(){var e,t,n;r.listTimer[i]=null,e=Math.round(Math.ceil(s.scrollTop())/40),n=(t=s.find(".js-"+i+"-"+e)).position().top-40*a.distance,s.find(".active").removeClass("active"),s[0].scrollTop=n,t.addClass("active"),v.exec(a.onScroll,[t,s,l],s[0])},150)))})})},_correct:function(){var e=this.value.getMonth(),t=this.value.getDate(),n=this.value.getFullYear();this.value=new Date(n,e,t)},_set:function(){var e=this.element,t=this.options,n=this.picker,i=this.locale.months[this.value.getMonth()],s=this.value.getDate(),a=this.value.getFullYear();!0===t.month&&n.find(".month").html(i),!0===t.day&&n.find(".day").html(s),!0===t.year&&n.find(".year").html(a),e.val(this.value.format(t.format,t.locale)).trigger("change"),v.exec(t.onSet,[this.value,e.val(),e,n],e[0]),e.fire("set",{value:this.value})},open:function(){var e,t,n,i,s,a=this.element,o=this.options,r=this.picker,l=this.value.getMonth(),c=this.value.getDate()-1,d=this.value.getFullYear(),u=r.find(".select-wrapper");u.parent().removeClass("for-top for-bottom"),u.show(0),r.find("li").removeClass("active"),i=v.inViewport(u[0]),s=v.rect(u[0]),!i&&0<s.top&&u.parent().addClass("for-bottom"),!i&&s.top<0&&u.parent().addClass("for-top"),!0===o.month&&(e=r.find(".sel-month")).scrollTop(0).animate({draw:{scrollTop:e.find("li.js-month-"+l).addClass("active").position().top-40*o.distance},dur:100}),!0===o.day&&(t=r.find(".sel-day")).scrollTop(0).animate({draw:{scrollTop:t.find("li.js-day-"+c).addClass("active").position().top-40*o.distance},dur:100}),!0===o.year&&(n=r.find(".sel-year")).scrollTop(0).animate({draw:{scrollTop:n.find("li.js-year-real-"+d).addClass("active").position().top-40*o.distance},dur:100}),this.isOpen=!0,v.exec(o.onOpen,[this.value,a,r],a[0]),a.fire("open",{value:this.value})},close:function(){var e=this.picker,t=this.options,n=this.element;e.find(".select-wrapper").hide(0),this.isOpen=!1,v.exec(t.onClose,[this.value,n,e],n[0]),n.fire("close",{value:this.value})},val:function(e){var t=this.options;if(!v.isValue(e))return this.element.val();v.isValue(t.inputFormat)?this.value=(""+e).toDate(t.inputFormat):this.value=new Date(e),this._set()},date:function(e){if(void 0===e)return this.value;try{this.value=new Date(e.format("%Y-%m-%d")),this._set()}catch(e){return!1}},i18n:function(e){var t,n,i=this.element,s=this.options;if(s.locale=e||i.attr("data-locale"),this.locale=o.locales[s.locale].calendar,!0===s.month){for(t=i.closest(".date-picker").find(".sel-month").html(""),n=0;n<s.distance;n++)m("<li>").html("&nbsp;").data("value",-1).appendTo(t);for(n=0;n<12;n++)m("<li>").addClass("js-month-"+n+" js-month-real-"+this.locale.months[n].toLowerCase()).html(this.locale.months[n]).data("value",n).appendTo(t);for(n=0;n<s.distance;n++)m("<li>").html("&nbsp;").data("value",-1).appendTo(t)}this._set()},changeAttribute:function(e){var t=this;switch(e){case"data-value":t.val(t.element.attr("data-value"));break;case"data-locale":t.i18n(t.element.attr("data-locale"));break;case"data-format":t.options.format=t.element.attr("data-format"),t._set()}},destroy:function(){var e=this.element,t=this.picker;return m.each(["moth","day","year"],function(){t.find(".sel-"+this).off("scroll")}),t.off(o.events.start,".select-block ul"),t.off(o.events.click),t.off(o.events.click,".action-ok"),t.off(o.events.click,".action-cancel"),e}}),m(document).on(o.events.click,function(){m.each(m(".date-picker"),function(){m(this).find("input").each(function(){o.getPlugin(this,"datepicker").close()})})})}(Metro,m4q),function(l,c){"use strict";var d=l.utils,n={dialogDeferred:0,closeButton:!1,leaveOverlayOnClose:!1,toTop:!1,toBottom:!1,locale:METRO_LOCALE,title:"",content:"",actions:{},actionsAlign:"right",defaultAction:!0,overlay:!0,overlayColor:"#000000",overlayAlpha:.5,overlayClickClose:!1,width:"480",height:"auto",shadow:!0,closeAction:!0,clsDialog:"",clsTitle:"",clsContent:"",clsAction:"",clsDefaultAction:"",clsOverlay:"",autoHide:0,removeOnClose:!1,show:!1,_runtime:!1,onShow:l.noop,onHide:l.noop,onOpen:l.noop,onClose:l.noop,onDialogCreate:l.noop};l.dialogSetup=function(e){n=c.extend({},n,e)},window.metroDialogSetup,l.dialogSetup(window.metroDialogSetup),l.Component("dialog",{_counter:0,init:function(e,t){return this._super(t,e,n,{interval:null,overlay:null,id:d.elementId("dialog")}),this},_create:function(){var e=this.options;this.locale=void 0!==l.locales[e.locale]?l.locales[e.locale]:l.locales["en-US"],this._build()},_build:function(){var e,t=this,n=this.element,i=this.options,s=c("body");if(n.addClass("dialog"),!0===i.shadow&&n.addClass("shadow-on"),""!==i.title&&this.setTitle(i.title),""!==i.content&&this.setContent(i.content),!0===i.defaultAction||!1!==i.actions&&"object"==typeof i.actions&&0<d.objectLength(i.actions)){var a,o=n.find(".dialog-actions");0===o.length&&(o=c("<div>").addClass("dialog-actions").addClass("text-"+i.actionsAlign).appendTo(n)),!0===i.defaultAction&&0===d.objectLength(i.actions)&&0===n.find(".dialog-actions > *").length&&(a=c("<button>").addClass("button js-dialog-close").addClass(i.clsDefaultAction).html(this.locale.buttons.ok)).appendTo(o),d.isObject(i.actions)&&c.each(d.isObject(i.actions),function(){var e=this;a=c("<button>").addClass("button").addClass(e.cls).html(e.caption),void 0!==e.onclick&&a.on(l.events.click,function(){d.exec(e.onclick,[n])}),a.appendTo(o)})}!0===i.overlay&&(e=this._overlay(),this.overlay=e),!0===i.closeAction&&n.on(l.events.click,".js-dialog-close",function(){t.close()});var r=n.find("closer");0===r.length&&(r=c("<span>").addClass("button square closer js-dialog-close")).appendTo(n),!0!==i.closeButton&&r.hide(),n.css({width:i.width,height:i.height,visibility:"hidden",top:"100%",left:(c(window).width()-n.outerWidth())/2}),n.addClass(i.clsDialog),n.find(".dialog-title").addClass(i.clsTitle),n.find(".dialog-content").addClass(i.clsContent),n.find(".dialog-actions").addClass(i.clsAction),n.appendTo(s),i.show&&this.open(),c(window).on(l.events.resize,function(){t.setPosition()},{ns:this.id}),this._fireEvent("dialog-create",{element:n})},_overlay:function(){var e=this.options,t=c("<div>");return t.addClass("overlay").addClass(e.clsOverlay),"transparent"===e.overlayColor?t.addClass("transparent"):t.css({background:d.hex2rgba(e.overlayColor,e.overlayAlpha)}),t},hide:function(e){var t=this.element,n=this.options,i=0;n.onHide!==l.noop&&(i=500,d.exec(n.onHide,null,t[0]),t.fire("hide")),setTimeout(function(){d.exec(e,null,t[0]),t.css({visibility:"hidden",top:"100%"})},i)},show:function(e){var t=this.element,n=this.options;this.setPosition(),t.css({visibility:"visible"}),d.exec(n.onShow,[this],t[0]),t.fire("show"),d.exec(e,null,t[0])},setPosition:function(){var e,t,n=this.element,i=this.options;!0!==i.toTop&&!0!==i.toBottom?((e=(c(window).height()-n.outerHeight())/2)<0&&(e=0),t="auto"):(!0===i.toTop&&(e=0,t="auto"),!0!==i.toTop&&!0===i.toBottom&&(t=0,e="auto")),n.css({top:e,bottom:t,left:(c(window).width()-n.outerWidth())/2})},setContent:function(e){var t=this.element,n=t.find(".dialog-content");0===n.length&&(n=c("<div>").addClass("dialog-content")).appendTo(t),!d.isQ(e)&&d.isFunc(e)&&(e=d.exec(e)),d.isQ(e)?e.appendTo(n):n.html(e)},setTitle:function(e){var t=this.element,n=t.find(".dialog-title");0===n.length&&(n=c("<div>").addClass("dialog-title")).appendTo(t),n.html(e)},close:function(){var e=this.element,t=this.options;d.bool(t.leaveOverlayOnClose)||c("body").find(".overlay").remove(),this.hide(function(){e.data("open",!1),d.exec(t.onClose,[e],e[0]),e.fire("close"),!0===t.removeOnClose&&e.remove()})},open:function(){var e=this,t=this.element,n=this.options;!0===n.overlay&&0===c(".overlay").length&&(this.overlay.appendTo(c("body")),!0===n.overlayClickClose&&this.overlay.on(l.events.click,function(){e.close()})),this.show(function(){d.exec(n.onOpen,[t],t[0]),t.fire("open"),t.data("open",!0),0<parseInt(n.autoHide)&&setTimeout(function(){e.close()},parseInt(n.autoHide))})},toggle:function(){this.element.data("open")?this.close():this.open()},isOpen:function(){return!0===this.element.data("open")},changeAttribute:function(e){},destroy:function(){var e=this.element;return e.off(l.events.click,".js-dialog-close"),e.find(".button").off(l.events.click),c(window).off(l.events.resize,{ns:this.id}),e}}),l.dialog={isDialog:function(e){return d.isMetroObject(e,"dialog")},open:function(e,t,n){if(!this.isDialog(e))return!1;var i=l.getPlugin(e,"dialog");void 0!==n&&i.setTitle(n),void 0!==t&&i.setContent(t),i.open()},close:function(e){if(!this.isDialog(e))return!1;l.getPlugin(c(e)[0],"dialog").close()},toggle:function(e){if(!this.isDialog(e))return!1;l.getPlugin(c(e)[0],"dialog").toggle()},isOpen:function(e){if(!this.isDialog(e))return!1;l.getPlugin(c(e)[0],"dialog").isOpen()},remove:function(e){if(!this.isDialog(e))return!1;var t=l.getPlugin(c(e)[0],"dialog");t.options.removeOnClose=!0,t.close()},create:function(e){var t;t=c("<div>").appendTo(c("body"));var n=c.extend({},{show:!0,closeAction:!0,removeOnClose:!0},void 0!==e?e:{});return n._runtime=!0,l.makePlugin(t,"dialog",n)}}}(Metro,m4q),function(e,u){"use strict";var h=e.utils,n={donutDeferred:0,size:100,radius:50,hole:.8,value:0,background:"#ffffff",color:"",stroke:"#d1d8e7",fill:"#49649f",fontSize:24,total:100,cap:"%",showText:!0,showValue:!1,animate:0,onChange:e.noop,onDonutCreate:e.noop};e.donutSetup=function(e){n=u.extend({},n,e)},window.metroDonutSetup,e.donutSetup(window.metroDonutSetup),e.Component("donut",{init:function(e,t){return this._super(t,e,n,{value:0,animation_change_interval:null}),this},_create:function(){var e=this.element,t=this.options,n="",i=t.radius*(1-(1-t.hole)/2),s=t.radius*(1-t.hole),a="rotate(-90 "+t.radius+","+t.radius+")",o=i*t.hole*.6;e.addClass("donut"),e.css({width:t.size,height:t.size,background:t.background}),n+="<svg>",n+="   <circle class='donut-back' r='"+i+"px' cx='"+t.radius+"px' cy='"+t.radius+"px' transform='"+a+"' fill='none' stroke='"+t.stroke+"' stroke-width='"+s+"'/>",n+="   <circle class='donut-fill' r='"+i+"px' cx='"+t.radius+"px' cy='"+t.radius+"px' transform='"+a+"' fill='none' stroke='"+t.fill+"' stroke-width='"+s+"'/>",!0===t.showText&&(n+="   <text   class='donut-title' x='"+t.radius+"px' y='"+t.radius+"px' dy='"+o/3+"px' text-anchor='middle' fill='"+(""!==t.color?t.color:t.fill)+"' font-size='"+o+"px'>0"+t.cap+"</text>"),n+="</svg>",e.html(n),this.val(t.value),this._fireEvent("donut-create",{element:e})},_setValue:function(e){var t=this.element,n=this.options,i=t.find(".donut-fill"),s=t.find(".donut-title"),a=n.radius*(1-(1-n.hole)/2),o=Math.round(2*Math.PI*a),r=n.showValue?e:h.percent(n.total,e,!0),l=Math.round(+e*o/n.total),c=i.attr("stroke-dasharray"),d=l-(c=void 0===c?0:+c.split(" ")[0]);i.animate({draw:function(e,t){u(this).attr("stroke-dasharray",c+d*t+" "+o)},dur:n.animate}),s.animate({draw:{innerHTML:r},dur:n.animate,onFrame:function(){this.innerHTML+=n.cap}})},val:function(e){var t=this.element,n=this.options;return void 0===e?this.value:!(parseInt(e)<0||parseInt(e)>n.total)&&(this._setValue(e),this.value=e,h.exec(n.onChange,[this.value],t[0]),void t.fire("change",{value:this.value}))},changeValue:function(){this.val(this.element.attr("data-value"))},changeAttribute:function(e){switch(e){case"data-value":this.changeValue()}},destroy:function(){return this.element}})}(Metro,m4q),function(u,h){"use strict";var p=u.utils,n={doublesliderDeferred:0,roundValue:!0,min:0,max:100,accuracy:0,showMinMax:!1,minMaxPosition:u.position.TOP,valueMin:null,valueMax:null,hint:!1,hintAlways:!1,hintPositionMin:u.position.TOP,hintPositionMax:u.position.TOP,hintMaskMin:"$1",hintMaskMax:"$1",target:null,size:0,clsSlider:"",clsBackside:"",clsComplete:"",clsMarker:"",clsMarkerMin:"",clsMarkerMax:"",clsHint:"",clsHintMin:"",clsHintMax:"",clsMinMax:"",clsMin:"",clsMax:"",onStart:u.noop,onStop:u.noop,onMove:u.noop,onChange:u.noop,onChangeValue:u.noop,onFocus:u.noop,onBlur:u.noop,onDoubleSliderCreate:u.noop};u.doubleSliderSetup=function(e){n=h.extend({},n,e)},window.metroDoubleSliderSetup,u.doubleSliderSetup(window.metroDoubleSliderSetup),u.Component("double-slider",{init:function(e,t){return this._super(t,e,n,{slider:null,valueMin:null,valueMax:null,keyInterval:!1,id:p.elementId("slider")}),this},_create:function(){var e=this.element,t=this.options;this.valueMin=p.isValue(t.valueMin)?+t.valueMin:+t.min,this.valueMax=p.isValue(t.valueMax)?+t.valueMax:+t.max,this._createSlider(),this._createEvents(),this.val(this.valueMin,this.valueMax),this._fireEvent("double-slider-create",{element:e})},_createSlider:function(){var e,t=this.element,n=this.options,i=h("<div>").addClass("slider").addClass(n.clsSlider).addClass(this.elem.className),s=h("<div>").addClass("backside").addClass(n.clsBackside),a=h("<div>").addClass("complete").addClass(n.clsComplete),o=h("<button>").attr("type","button").addClass("marker marker-min").addClass(n.clsMarker).addClass(n.clsMarkerMin),r=h("<button>").attr("type","button").addClass("marker marker-max").addClass(n.clsMarker).addClass(n.clsMarkerMax),l=h("<div>").addClass("hint hint-min").addClass(n.hintPositionMin+"-side").addClass(n.clsHint).addClass(n.clsHintMin),c=h("<div>").addClass("hint hint-max").addClass(n.hintPositionMax+"-side").addClass(n.clsHint).addClass(n.clsHintMax);if(0<n.size&&i.outerWidth(n.size),i.insertBefore(t),t.appendTo(i),s.appendTo(i),a.appendTo(i),o.appendTo(i),r.appendTo(i),l.appendTo(o),c.appendTo(r),!0===n.hintAlways&&h([l,c]).css({display:"block"}).addClass("permanent-hint"),!0===n.showMinMax){var d=h("<div>").addClass("slider-min-max clear").addClass(n.clsMinMax);h("<span>").addClass("place-left").addClass(n.clsMin).html(n.min).appendTo(d),h("<span>").addClass("place-right").addClass(n.clsMax).html(n.max).appendTo(d),n.minMaxPosition===u.position.TOP?d.insertBefore(i):d.insertAfter(i)}if(!(t[0].className="")===n.copyInlineStyles)for(e=0;e<t[0].style.length;e++)i.css(t[0].style[e],t.css(t[0].style[e]));t.is(":disabled")?this.disable():this.enable(),this.slider=i},_createEvents:function(){var t=this,e=this.slider,n=this.options,i=e.find(".marker");i.on(u.events.startAll,function(){var e=h(this).find(".hint");!0===n.hint&&!0!==n.hintAlways&&e.fadeIn(300),h(document).on(u.events.moveAll,function(e){t._move(e),t._fireEvent("move",{min:t.valueMin,max:t.valueMax})},{ns:t.id}),h(document).on(u.events.stopAll,function(){h(document).off(u.events.moveAll,{ns:t.id}),h(document).off(u.events.stopAll,{ns:t.id}),!0!==n.hintAlways&&e.fadeOut(300),t._fireEvent("stop",{min:t.valueMin,max:t.valueMax})},{ns:t.id}),t._fireEvent("start",{min:t.valueMin,max:t.valueMax})}),i.on(u.events.focus,function(){t._fireEvent("focus",{min:t.valueMin,max:t.valueMax})}),i.on(u.events.blur,function(){t._fireEvent("blur",{min:t.valueMin,max:t.valueMax})}),h(window).on(u.events.resize,function(){t.val(t.valueMin,t.valueMax)},{ns:t.id})},_convert:function(e,t){var n=this.slider,i=this.options,s=n.outerWidth()-n.find(".marker").outerWidth();switch(t){case"pix2prc":return 100*e/s;case"pix2val":return this._convert(e,"pix2prc")*((i.max-i.min)/100)+i.min;case"val2prc":return(e-i.min)/((i.max-i.min)/100);case"prc2pix":return e/(100/s);case"val2pix":return this._convert(this._convert(e,"val2prc"),"prc2pix")}return 0},_correct:function(e){var t,n=e,i=this.options.accuracy,s=this.options.min,a=this.options.max;return 0===i||isNaN(i)?n:((n=Math.round(e/i)*i)<s&&(n=s),a<n&&(n=a),n.toFixed((t=i)%1==0?0:t.toString().split(".")[1].length))},_move:function(e){var t,n,i,s=h(e.target).hasClass("marker-min"),a=this.slider,o=a.offset(),r=a.find(".marker").outerWidth(),l=a.find(".marker-min"),c=a.find(".marker-max"),d=a.outerWidth();t=p.pageXY(e).x-o.left-r/2,i=s?(n=0,parseInt(c.css("left"))-r):(n=parseInt(l.css("left"))+r,d-r),t<n||i<t||(this[s?"valueMin":"valueMax"]=this._correct(this._convert(t,"pix2val")),this._redraw())},_hint:function(){var s=this,a=this.options;this.slider.find(".hint").each(function(){var e=h(this),t=e.hasClass("hint-min"),n=t?a.hintMaskMin:a.hintMaskMax,i=+(t?s.valueMin:s.valueMax)||0;e.text(n.replace("$1",i.toFixed(p.decCount(a.accuracy))))})},_value:function(){var t,e=this.element,n=this.options,i=+this.valueMin||0,s=+this.valueMax||0;if(n.roundValue&&(i=i.toFixed(p.decCount(n.accuracy)),s=s.toFixed(p.decCount(n.accuracy))),t=[i,s].join(", "),"INPUT"===e[0].tagName&&e.val(t),null!==n.target){var a=h(n.target);0!==a.length&&h.each(a,function(){var e=h(this);"INPUT"===this.tagName?e.val(t):e.text(t),e.trigger("change")})}this._fireEvent("change-value",{val:t}),this._fireEvent("change",{val:t})},_marker:function(){var e=this.slider,t=e.find(".marker-min"),n=e.find(".marker-max"),i=e.find(".complete"),s=parseInt(p.getStyleOne(t,"width")),a=p.isVisible(e);a&&h([t,n]).css({"margin-top":0,"margin-left":0}),a?(t.css("left",this._convert(this.valueMin,"val2pix")),n.css("left",this._convert(this.valueMax,"val2pix"))):(t.css({left:this._convert(this.valueMin,"val2prc")+"%","margin-top":0===this._convert(this.valueMin,"val2prc")?0:-1*s/2}),n.css({left:this._convert(this.valueMax,"val2prc")+"%","margin-top":0===this._convert(this.valueMax,"val2prc")?0:-1*s/2})),i.css({left:this._convert(this.valueMin,"val2pix"),width:this._convert(this.valueMax,"val2pix")-this._convert(this.valueMin,"val2pix")})},_redraw:function(){this._marker(),this._value(),this._hint()},val:function(e,t){var n=this.options;if(!p.isValue(e)&&!p.isValue(t))return[this.valueMin,this.valueMax];e<n.min&&(e=n.min),t<n.min&&(t=n.min),e>n.max&&(e=n.max),t>n.max&&(t=n.max),this.valueMin=this._correct(e),this.valueMax=this._correct(t),this._redraw()},changeValue:function(){var e=this.element,t=+e.attr("data-value-min"),n=+e.attr("data-value-max");this.val(t,n)},disable:function(){var e=this.element;e.data("disabled",!0),e.parent().addClass("disabled")},enable:function(){var e=this.element;e.data("disabled",!1),e.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},changeAttribute:function(e){switch(e){case"data-value-min":case"data-value-max":this.changeValue();break;case"disabled":this.toggleState()}},destroy:function(){var e=this.element,t=this.slider,n=t.find(".marker");return n.off(u.events.startAll),n.off(u.events.focus),n.off(u.events.blur),n.off(u.events.keydown),n.off(u.events.keyup),t.off(u.events.click),h(window).off(u.events.resize,{ns:this.id}),e}})}(Metro,m4q),function(c,C){"use strict";var b=c.utils,n={dragitemsDeferred:0,target:null,dragItem:"li",dragMarker:".drag-item-marker",drawDragMarker:!1,clsDragItemAvatar:"",clsDragItem:"",canDrag:!0,onDragStartItem:c.noop,onDragMoveItem:c.noop,onDragDropItem:c.noop,onTarget:c.noop,onTargetIn:c.noop,onTargetOut:c.noop,onDragItemsCreate:c.noop};c.dragItemsSetup=function(e){n=C.extend({},n,e)},window.metroDragItemsSetup,c.dragItemsSetup(window.metroDragItemsSetup),c.Component("drag-items",{init:function(e,t){return this._super(t,e,n,{id:b.elementId("dragItems"),canDrag:!1}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("drag-items-create",{element:e})},_createStructure:function(){var e=this.element,t=this.options;e.addClass("drag-items-target"),!0===t.drawDragMarker&&e.find(t.dragItem).each(function(){C("<span>").addClass("drag-item-marker").appendTo(this)}),t.canDrag?this.on():this.off()},_createEvents:function(){var i,s,a,o=this,v=this.element,g=this.options,r=C.document(),l=C.body(),w={top:0,left:0};v.on(c.events.startAll,g.drawDragMarker?g.dragMarker:g.dragItem,function(e){var t,n=C(e.target).closest(g.dragItem);b.isRightMouse(e)||!0===o.canDrag&&(n.addClass("dragged-item").addClass(g.clsDragItem),t=C("<div>").addClass("dragged-item-avatar").addClass(g.clsDragItemAvatar),i=n.offset(),s=n.width(),a=n.height(),w.top=b.pageXY(e).y-i.top,w.left=b.pageXY(e).x-i.left,t.css({top:i.top,left:i.left,width:s,height:a}).appendTo(l),b.exec(g.onDragStartItem,[n[0],t[0]],v[0]),v.fire("dragstartitem",{dragItem:n[0],avatar:t[0]}),r.on(c.events.moveAll,function(e){!function(e,t,n){var i=b.pageXY(e).x,s=b.pageXY(e).y,a=s-w.top,o=i-w.left;t.css({top:a,left:o});var r=document.elementsFromPoint(i,s).filter(function(e){return C(e).hasClass("drag-items-target")});if(0!==r.length){b.exec(g.onTarget,[r],v[0]),v.fire("target",{target:r});var l=document.elementsFromPoint(i,s).filter(function(e){var t=C(e);return C.matches(e,g.dragItem)&&!t.hasClass("dragged-item-avatar")})[0];if(b.isValue(l)){var c,d=C(l),u=d.offset(),h=s-u.top,p=i-u.left,f=d.width(),m=d.height();c=p<f/3&&(h<m/2||m/2<h)?"left":2*f/3<p&&(h<m/2||m/2<h)?"right":f/3<p&&p<2*f/3&&m/2<h?"bottom":"top",d.hasClass("dragged-item")||("top"===c||"left"===c?n.insertBefore(d):n.insertAfter(d))}else n.appendTo(r)}}(e,t,n),b.exec(g.onDragMoveItem,[n[0],t[0]],v[0]),v.fire("dragmoveitem",{dragItem:n[0],avatar:t[0]}),e.preventDefault()},{ns:o.id,passive:!1}),r.on(c.events.stopAll,function(){b.exec(g.onDragDropItem,[n[0],t[0]],v[0]),v.fire("dragdropitem",{dragItem:n[0],avatar:t[0]}),n.removeClass("dragged-item").removeClass(g.clsDragItem),t.remove(),r.off(c.events.moveAll,{ns:o.id}),r.off(c.events.stopAll,{ns:o.id})},{ns:o.id}),g.drawDragMarker&&(e.preventDefault(),e.stopPropagation()))})},on:function(){this.canDrag=!0,this.element.find(".drag-item-marker").show()},off:function(){this.canDrag=!1,this.element.find(".drag-item-marker").hide()},toggle:function(){this.canDrag=this.canDrag?this.off():this.on()},changeAttribute:function(e){var t=this,n=this.element,i=this.options;"data-can-drag"===e&&(i.canDtag=JSON.parse(n.attr("data-can-drag")),i.canDtag?t.on():t.off())},destroy:function(){var e=this.element,t=this.options;return e.off(c.events.startAll,t.drawDragMarker?t.dragMarker:t.dragItem),e}})}(Metro,m4q),function(c,d){"use strict";var u=c.utils,n={dragContext:null,draggableDeferred:0,dragElement:"self",dragArea:"parent",timeout:0,onCanDrag:c.noop_true,onDragStart:c.noop,onDragStop:c.noop,onDragMove:c.noop,onDraggableCreate:c.noop};c.draggableSetup=function(e){n=d.extend({},n,e)},window.metroDraggableSetup,c.draggableSetup(window.metroDraggableSetup),c.Component("draggable",{init:function(e,t){return this._super(t,e,n,{drag:!1,move:!1,backup:{cursor:"default",zIndex:"0"},dragArea:null,dragElement:null,id:u.elementId("draggable")}),this},_create:function(){this._createStructure(),this._createEvents(),this._fireEvent("draggable-create",{element:this.element})},_createStructure:function(){var e=this,t=this.element,n=this.options,i=t.offset(),s="self"!==n.dragElement?t.find(n.dragElement):t;t.data("canDrag",!0),(this.dragElement=s)[0].ondragstart=function(){return!1},t.css("position","absolute"),"document"!==n.dragArea&&"window"!==n.dragArea||(n.dragArea="body"),setImmediate(function(){e.dragArea="parent"===n.dragArea?t.parent():d(n.dragArea),"parent"!==n.dragArea&&(t.appendTo(e.dragArea),t.css({top:i.top,left:i.left}))}),t.attr("id")||t.attr("id",u.elementId("draggable"))},_createEvents:function(){var a=this,o=this.element,r=this.options,l={x:0,y:0};this.dragElement.on(c.events.startAll,function(e){function t(e){var t=u.pageXY(e).y-s,n=u.pageXY(e).x-i;t<0&&(t=0),n<0&&(n=0),t>a.dragArea.outerHeight()-o.outerHeight()&&(t=a.dragArea.outerHeight()-o.outerHeight()),n>a.dragArea.outerWidth()-o.outerWidth()&&(n=a.dragArea.outerWidth()-o.outerWidth()),l.y=t,l.x=n,o.css({left:n,top:t})}var n="parent"!==r.dragArea?o.offset():o.position(),i=u.pageXY(e).x-n.left,s=u.pageXY(e).y-n.top;!1!==o.data("canDrag")&&!0===u.exec(r.onCanDrag,[o])&&(!1===c.isTouchable&&1!==e.which||(a.drag=!0,a.backup.cursor=o.css("cursor"),a.backup.zIndex=o.css("z-index"),o.addClass("draggable"),t(e),a._fireEvent("drag-start",{position:l,context:r.dragContext}),d(document).on(c.events.moveAll,function(e){e.preventDefault(),t(e),a._fireEvent("drag-move",{position:l,context:r.dragContext})},{ns:a.id,passive:!1}),d(document).on(c.events.stopAll,function(){o.css({cursor:a.backup.cursor,zIndex:a.backup.zIndex}).removeClass("draggable"),a.drag&&(d(document).off(c.events.moveAll,{ns:a.id}),d(document).off(c.events.stopAll,{ns:a.id})),a.drag=!1,a.move=!1,a._fireEvent("drag-stop",{position:l,context:r.dragContext})},{ns:a.id})))})},off:function(){this.element.data("canDrag",!1)},on:function(){this.element.data("canDrag",!0)},changeAttribute:function(e,t){},destroy:function(){var e=this.element;return this.dragElement.off(c.events.startAll),e}})}(Metro,m4q),function(o,r){"use strict";var l=o.utils,n={dropdownDeferred:0,dropFilter:null,toggleElement:null,noClose:!1,duration:50,onDrop:o.noop,onUp:o.noop,onDropdownCreate:o.noop};o.dropdownSetup=function(e){n=r.extend({},n,e)},window.metroDropdownSetup,o.dropdownSetup(window.metroDropdownSetup),o.Component("dropdown",{init:function(e,t){return this._super(t,e,n,{_toggle:null,displayOrigin:null,isOpen:!1}),this},_create:function(){var e=this,t=this.element;this._createStructure(),this._createEvents(),this._fireEvent("dropdown-create",{element:t}),t.hasClass("open")&&(t.removeClass("open"),setImmediate(function(){e.open(!0)}))},_createStructure:function(){var e,t=this.element,n=this.options;e=null!==n.toggleElement?r(n.toggleElement):0<t.siblings(".dropdown-toggle").length?t.siblings(".dropdown-toggle"):t.prev(),this.displayOrigin=l.getStyleOne(t,"display"),t.hasClass("v-menu")&&t.addClass("for-dropdown"),t.css("display","none"),this._toggle=e},_createEvents:function(){var n=this,i=this.element,s=this.options,e=this._toggle,a=i.parent();e.on(o.events.click,function(e){if(a.siblings(a[0].tagName).removeClass("active-container"),r(".active-container").removeClass("active-container"),"none"===i.css("display")||i.hasClass("keep-open")){if(r("[data-role=dropdown]").each(function(e,t){i.parents("[data-role=dropdown]").is(t)||r(t).hasClass("keep-open")||"none"===r(t).css("display")||(l.isValue(s.dropFilter)?0<r(t).closest(s.dropFilter).length&&n._close(t):n._close(t))}),i.hasClass("horizontal")){i.css({visibility:"hidden",display:"block"});var t=0;r.each(i.children("li"),function(){t+=r(this).outerWidth(!0)}),i.css({visibility:"visible",display:"none"}),i.css("width",t)}n._open(i),a.addClass("active-container")}else n._close(i);e.preventDefault(),e.stopPropagation()}),!0===s.noClose&&i.addClass("keep-open").on(o.events.click,function(e){e.stopPropagation()}),r(i).find("li.disabled a").on(o.events.click,function(e){e.preventDefault()})},_close:function(e,t){e=r(e);var n=o.getPlugin(e,"dropdown"),i=n._toggle,s=n.options,a="slideUp";i.removeClass("active-toggle").removeClass("active-control"),n.element.parent().removeClass("active-container"),t&&(a="hide"),e[a](t?0:s.duration,function(){e.trigger("onClose",null,e)}),this._fireEvent("up"),this.isOpen=!1},_open:function(e,t){e=r(e);var n=o.getPlugin(e,"dropdown"),i=n._toggle,s=n.options;i.addClass("active-toggle").addClass("active-control"),e.slideDown(t?0:s.duration,function(){e.fire("onopen")}),this._fireEvent("drop"),this.isOpen=!0},close:function(e){this._close(this.element,e)},open:function(e){this._open(this.element,e)},toggle:function(){this.isOpen?this.close():this.open()},changeAttribute:function(e){},destroy:function(){this._toggle.off(o.events.click)}}),r(document).on(o.events.click,function(){r("[data-role*=dropdown]").each(function(){var e=r(this);"none"===e.css("display")||e.hasClass("keep-open")||e.hasClass("stay-open")||e.hasClass("ignore-document-click")||o.getPlugin(e,"dropdown").close()})})}(Metro,m4q),function(r,c){"use strict";var l=r.utils,n={fileDeferred:0,mode:"input",buttonTitle:"Choose file(s)",filesTitle:"file(s) selected",dropTitle:"<strong>Choose a file(s)</strong> or drop it here",dropIcon:"<span class='default-icon-upload'></span>",prepend:"",clsComponent:"",clsPrepend:"",clsButton:"",clsCaption:"",copyInlineStyles:!1,onSelect:r.noop,onFileCreate:r.noop};r.fileSetup=function(e){n=c.extend({},n,e)},window.metroFileSetup,r.fileSetup(window.metroFileSetup),r.Component("file",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("file-create",{element:e})},_createStructure:function(){var e,t,n=this.element,i=this.options,s=c("<label>").addClass(("input"===i.mode?" file ":"button"===i.mode?" file-button ":" drop-zone ")+n[0].className).addClass(i.clsComponent),a=c("<span>").addClass("caption").addClass(i.clsCaption),o=c("<span>").addClass("files").addClass(i.clsCaption);if(s.insertBefore(n),n.appendTo(s),"drop"===i.mode||"dropzone"===i.mode)e=c(i.dropIcon).addClass("icon").appendTo(s),a.html(i.dropTitle).insertAfter(e),o.html("0 "+i.filesTitle).insertAfter(a);else if("button"===i.mode)(t=c("<span>").addClass("button").attr("tabindex",-1).html(i.buttonTitle)).appendTo(s),t.addClass(i.clsButton);else{if(a.insertBefore(n),(t=c("<span>").addClass("button").attr("tabindex",-1).html(i.buttonTitle)).appendTo(s),t.addClass(i.clsButton),"rtl"===n.attr("dir")&&s.addClass("rtl"),""!==i.prepend)c("<div>").html(i.prepend).addClass("prepend").addClass(i.clsPrepend).appendTo(s)}if(!(n[0].className="")===i.copyInlineStyles)for(var r=0,l=n[0].style.length;r<l;r++)s.css(n[0].style[r],n.css(n[0].style[r]));n.is(":disabled")?this.disable():this.enable()},_createEvents:function(){var e=this,n=this.element,i=this.options,t=n.closest("label"),s=t.find(".caption"),a=t.find(".files"),o=n.closest("form");o.length&&o.on("reset",function(){e.clear()}),t.on(r.events.click,"button",function(){n[0].click()}),n.on(r.events.change,function(){var e,t=[];Array.from(this.files).forEach(function(e){t.push(e.name)}),"input"===i.mode?(e=t.join(", "),s.html(e),s.attr("title",e)):a.html(n[0].files.length+" "+i.filesTitle),l.exec(i.onSelect,[this.files],n[0]),n.fire("select",{files:this.files})}),n.on(r.events.focus,function(){t.addClass("focused")}),n.on(r.events.blur,function(){t.removeClass("focused")}),"input"!==i.mode&&(t.on("drag dragstart dragend dragover dragenter dragleave drop",function(e){e.preventDefault()}),t.on("dragenter dragover",function(){t.addClass("drop-on")}),t.on("dragleave",function(){t.removeClass("drop-on")}),t.on("drop",function(e){n[0].files=e.dataTransfer.files,a.html(n[0].files.length+" "+i.filesTitle),t.removeClass("drop-on"),n.trigger("change")}))},clear:function(){var e=this.element,t=this.options;"input"===t.mode?e.siblings(".caption").html(""):(e.siblings(".caption").html(t.dropTitle),e.siblings(".files").html("0 "+t.filesTitle)),e.val("")},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},toggleDir:function(){"rtl"===this.element.attr("dir")?this.element.parent().addClass("rtl"):this.element.parent().removeClass("rtl")},changeAttribute:function(e){switch(e){case"disabled":this.toggleState();break;case"dir":this.toggleDir()}},destroy:function(){var e=this.element,t=e.parent();return e.off(r.events.change),t.off(r.events.click,"button"),e}})}(Metro,m4q),function(i,a){"use strict";var s=i.utils,n={gravatarDeferred:0,email:"",size:80,default:"mp",onGravatarCreate:i.noop};i.gravatarSetup=function(e){n=a.extend({},n,e)},window.metroGravatarSetup,i.gravatarSetup(window.metroGravatarSetup),i.Component("gravatar",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e=this.element;this.get(),this._fireEvent("gravatar-create",{element:e})},getImage:function(e,t,n,i){var s=a("<img>").attr("alt",e);return s.attr("src",this.getImageSrc(e,t)),!0===i?s:s[0]},getImageSrc:function(e,t,n){return void 0===e||""===e.trim()?"":(t=t||80,n=s.encodeURI(n)||"404","//www.gravatar.com/avatar/"+i.md5(e.toLowerCase().trim())+"?size="+t+"&d="+n)},get:function(){var e=this.element,t=this.options,n="IMG"===e[0].tagName?e:e.find("img");if(0!==n.length)return n.attr("src",this.getImageSrc(t.email,t.size,t.default)),this},resize:function(e){this.options.size=void 0!==e?e:this.element.attr("data-size"),this.get()},email:function(e){this.options.email=void 0!==e?e:this.element.attr("data-email"),this.get()},changeAttribute:function(e){switch(e){case"data-size":this.resize();break;case"data-email":this.email()}},destroy:function(){return this.element}})}(Metro,m4q),function(a,o){"use strict";var r=a.utils,n={hintDeferred:0,hintHide:5e3,clsHint:"",hintText:"",hintPosition:a.position.TOP,hintOffset:4,onHintShow:a.noop,onHintHide:a.noop,onHintCreate:a.noop};a.hintSetup=function(e){n=o.extend({},n,e)},window.metroHintSetup,a.hintSetup(window.metroHintSetup),a.Component("hint",{init:function(e,t){return this._super(t,e,n,{hint:null,hint_size:{width:0,height:0},id:r.elementId("hint")}),this},_create:function(){this._createEvents(),this._fireEvent("hint-create",{element:this.element})},_createEvents:function(){var e=this,t=this.element,n=this.options;t.on(a.events.enter,function(){e.createHint(),0<+n.hintHide&&setTimeout(function(){e.removeHint()},n.hintHide)}),t.on(a.events.leave,function(){e.removeHint()}),o(window).on(a.events.scroll+" "+a.events.resize,function(){null!==e.hint&&e.setPosition()},{ns:this.id})},createHint:function(){var e=this.elem,t=this.element,n=this.options,i=o("<div>").addClass("hint").addClass(n.clsHint).html(n.hintText);if(this.hint=i,this.hint_size=r.hiddenElementSize(i),o(".hint:not(.permanent-hint)").remove(),"TD"===e.tagName||"TH"===e.tagName){var s=o("<div/>").css("display","inline-block").html(t.html());t.html(s),t=s}this.setPosition(),i.appendTo(o("body")),r.exec(n.onHintShow,[i[0]],t[0]),t.fire("hintshow",{hint:i[0]})},setPosition:function(){var e=this.hint,t=this.hint_size,n=this.options,i=this.element;n.hintPosition===a.position.BOTTOM?(e.addClass("bottom"),e.css({top:i.offset().top-o(window).scrollTop()+i.outerHeight()+n.hintOffset,left:i.offset().left+i.outerWidth()/2-t.width/2-o(window).scrollLeft()})):n.hintPosition===a.position.RIGHT?(e.addClass("right"),e.css({top:i.offset().top+i.outerHeight()/2-t.height/2-o(window).scrollTop(),left:i.offset().left+i.outerWidth()-o(window).scrollLeft()+n.hintOffset})):n.hintPosition===a.position.LEFT?(e.addClass("left"),e.css({top:i.offset().top+i.outerHeight()/2-t.height/2-o(window).scrollTop(),left:i.offset().left-t.width-o(window).scrollLeft()-n.hintOffset})):(e.addClass("top"),e.css({top:i.offset().top-o(window).scrollTop()-t.height-n.hintOffset,left:i.offset().left-o(window).scrollLeft()+i.outerWidth()/2-t.width/2}))},removeHint:function(){var e=this,t=this.hint,n=this.element,i=this.options,s=i.onHintHide===a.noop?0:300;null!==t&&(r.exec(i.onHintHide,[t[0]],n[0]),n.fire("hinthide",{hint:t[0]}),setTimeout(function(){t.hide(0,function(){t.remove(),e.hint=null})},s))},changeText:function(){this.options.hintText=this.element.attr("data-hint-text")},changeAttribute:function(e){"data-hint-text"===e&&this.changeText()},destroy:function(){var e=this.element;this.removeHint(),e.off(a.events.enter+"-hint"),e.off(a.events.leave+"-hint"),o(window).off(a.events.scroll+"-hint")}})}(Metro,m4q),function(o,r){"use strict";var l=o.utils,c={specialKeys:{8:"backspace",9:"tab",13:"return",16:"shift",17:"ctrl",18:"alt",19:"pause",20:"capslock",27:"esc",32:"space",33:"pageup",34:"pagedown",35:"end",36:"home",37:"left",38:"up",39:"right",40:"down",45:"insert",46:"del",96:"0",97:"1",98:"2",99:"3",100:"4",101:"5",102:"6",103:"7",104:"8",105:"9",106:"*",107:"+",109:"-",110:".",111:"/",112:"f1",113:"f2",114:"f3",115:"f4",116:"f5",117:"f6",118:"f7",119:"f8",120:"f9",121:"f10",122:"f11",123:"f12",144:"numlock",145:"scroll",188:",",190:".",191:"/",224:"meta"},shiftNums:{"~":"`","!":"1","@":"2","#":"3",$:"4","%":"5","^":"6","&":"7","*":"8","(":"9",")":"0",_:"-","+":"=",":":";",'"':"'","<":",",">":".","?":"/","|":"\\"},shiftNumsInverse:{"`":"~",1:"!",2:"@",3:"#",4:"$",5:"%",6:"^",7:"&",8:"*",9:"(",0:")","-":"_","=":"+",";":": ","'":'"',",":"<",".":">","/":"?","\\":"|"},textAcceptingInputTypes:["text","password","number","email","url","range","date","month","week","time","datetime","datetime-local","search","color","tel"],getKey:function(e){var t,n=e.keyCode,i=String.fromCharCode(n).toLowerCase();return t=e.shiftKey?c.shiftNums[i]?c.shiftNums[i]:i:void 0===c.specialKeys[n]?i:c.specialKeys[n],c.getModifier(e).length?c.getModifier(e).join("+")+"+"+t:t},getModifier:function(e){var t=[];return e.altKey&&t.push("alt"),e.ctrlKey&&t.push("ctrl"),e.shiftKey&&t.push("shift"),t}};function e(s,a){return this.each(function(){r(this).on(o.events.keyup+".hotkey-method-"+s,function(e){var t=c.getKey(e),n=r(this),i=""+n.attr("href");s===t&&(n.is("a")&&i&&"#"!==i.trim()&&(window.location.href=i),l.exec(a,[e,t,s],this))})})}r.fn.hotkey=e,window.METRO_JQUERY&&window.jquery_present&&(jQuery.fn.hotkey=e),r(document).on(o.events.keyup+".hotkey-data",function(e){var t,n,i,s;METRO_HOTKEYS_FILTER_INPUT_ACCEPTING_ELEMENTS&&/textarea|input|select/i.test(e.target.nodeName)||METRO_HOTKEYS_FILTER_CONTENT_EDITABLE&&r(e.target).attr("contenteditable")||METRO_HOTKEYS_FILTER_TEXT_INPUTS&&-1<c.textAcceptingInputTypes.indexOf(e.target.type)||(i=c.getKey(e),l.keyInObject(o.hotkeys,i)&&(t=r(o.hotkeys[i][0]),n=o.hotkeys[i][1],s=(""+t.attr("href")).trim(),n?l.exec(n):t.is("a")&&s&&0<s.length&&"#"!==s.trim()?window.location.href=s:t.click()))})}(Metro,m4q),function(e,a){"use strict";var r=e.utils,n={htmlcontainerDeferred:0,method:"get",htmlSource:null,requestData:null,requestOptions:null,insertMode:"default",onHtmlLoad:e.noop,onHtmlLoadFail:e.noop,onHtmlLoadDone:e.noop,onHtmlContainerCreate:e.noop};e.htmlContainerSetup=function(e){n=a.extend({},n,e)},window.metroHtmlContainerSetup,e.htmlContainerSetup(window.metroHtmlContainerSetup),e.Component("html-container",{init:function(e,t){return this._super(t,e,n,{data:{},opt:{},htmlSource:""}),this},_create:function(){var e=this.element,t=this.options;"string"==typeof t.requestData&&(t.requestData=JSON.parse(t.requestData)),r.isObject(t.requestData)&&(this.data=r.isObject(t.requestData)),"string"==typeof t.requestOptions&&(t.requestOptions=JSON.parse(t.requestOptions)),r.isObject(t.requestOptions)&&(this.opt=r.isObject(t.requestOptions)),t.method=t.method.toLowerCase(),r.isValue(t.htmlSource)&&(this.htmlSource=t.htmlSource,this._load()),this._fireEvent("html-container-create",{element:e})},_load:function(){var n=this,i=this.element,s=this.options;a[s.method](this.htmlSource,this.data,this.opt).then(function(e){var t=a(e);switch(0===t.length&&(t=a("<div>").html(e)),s.insertMode.toLowerCase()){case"prepend":i.prepend(t);break;case"append":i.append(t);break;case"replace":t.insertBefore(i).script(),i.remove();break;default:i.html(t)}n._fireEvent("html-load",{data:e,source:s.htmlSource,requestData:n.data,requestOptions:n.opt})},function(e){n._fireEvent("html-load-fail",{xhr:e})})},load:function(e,t,n){e&&(this.htmlSource=e),t&&(this.data=r.isObject(t)),n&&(this.opt=r.isObject(n)),this._load()},changeAttribute:function(e){var t,n,i,s=this,a=this.element,o=this.options;switch(e){case"data-html-source":i=a.attr("data-html-source"),r.isNull(i)||(""===i.trim()&&a.html(""),o.htmlSource=i,s._load());break;case"data-insert-mode":n=a.attr("data-insert-mode"),r.isValue(n)&&(o.insertMode=n);break;case"data-request-data":t=a.attr("data-request-data"),s.load(o.htmlSource,t)}},destroy:function(){}})}(Metro,m4q),function(t,l){"use strict";var c=t.utils,n={imagecompareDeferred:0,width:"100%",height:"auto",onResize:t.noop,onSliderMove:t.noop,onImageCompareCreate:t.noop};t.imageCompareSetup=function(e){n=l.extend({},n,e)},window.metroImageCompareSetup,t.imageCompareSetup(window.metroImageCompareSetup),t.Component("image-compare",{init:function(e,t){return this._super(t,e,n,{id:c.elementId("image-compare")}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("image-compare-create",{element:e})},_createStructure:function(){var n,i,e,t,s,a,o=this.element,r=this.options;switch(c.isValue(o.attr("id"))||o.attr("id",c.elementId("image-compare")),o.addClass("image-compare").css({width:r.width}),s=o.width(),r.height){case"16/9":case"21/9":case"4/3":a=c.aspectRatioH(s,r.height);break;case"auto":a=c.aspectRatioH(s,"16/9");break;default:a=r.height}o.css({height:a}),n=l("<div>").addClass("image-container").appendTo(o),i=l("<div>").addClass("image-container-overlay").appendTo(o).css({width:s/2}),(e=l("<div>").addClass("image-slider").appendTo(o)).css({top:a/2-e.height()/2,left:s/2-e.width()/2}),t=o.find("img"),l.each(t,function(e){var t=l("<div>").addClass("image-wrapper");t.css({width:s,height:a,backgroundImage:"url("+this.src+")"}),t.appendTo(0===e?n:i)})},_createEvents:function(){var e=this,s=this.element,a=this.options,o=s.find(".image-container-overlay"),r=s.find(".image-slider");r.on(t.events.startAll,function(){var i=s.width();l(document).on(t.events.moveAll,function(e){var t,n=c.getCursorPositionX(s[0],e);n<0&&(n=0),i<n&&(n=i),o.css({width:n}),t=n-r.width()/2,r.css({left:t}),c.exec(a.onSliderMove,[n,t],r[0]),s.fire("slidermove",{x:n,l:t})},{ns:e.id}),l(document).on(t.events.stopAll,function(){l(document).off(t.events.moveAll,{ns:e.id}),l(document).off(t.events.stopAll,{ns:e.id})},{ns:e.id})}),l(window).on(t.events.resize,function(){var e,t=s.width();if("100%"===a.width){switch(a.height){case"16/9":case"21/9":case"4/3":e=c.aspectRatioH(t,a.height);break;case"auto":e=c.aspectRatioH(t,"16/9");break;default:e=a.height}s.css({height:e}),l.each(s.find(".image-wrapper"),function(){l(this).css({width:t,height:e})}),s.find(".image-container-overlay").css({width:t/2}),r.css({top:e/2-r.height()/2,left:t/2-r.width()/2}),c.exec(a.onResize,[t,e],s[0]),s.fire("comparerresize",{width:t,height:e})}},{ns:this.id})},changeAttribute:function(e){},destroy:function(){var e=this.element;return e.off(t.events.start),l(window).off(t.events.resize,{ns:this.id}),e}})}(Metro,m4q),function(t,h){"use strict";var p=t.utils,n={imagemagnifierDeferred:0,width:"100%",height:"auto",lensSize:100,lensType:"square",magnifierZoom:2,magnifierMode:"glass",magnifierZoomElement:null,clsMagnifier:"",clsLens:"",clsZoom:"",onMagnifierMove:t.noop,onImageMagnifierCreate:t.noop};t.imageMagnifierSetup=function(e){n=h.extend({},n,e)},window.metroImageMagnifierSetup,t.imageMagnifierSetup(window.metroImageMagnifierSetup),t.Component("image-magnifier",{init:function(e,t){return this._super(t,e,n,{zoomElement:null,id:p.elementId("image-magnifier")}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("image-magnifier-create",{element:e})},_createStructure:function(){var e,t,n,i=this.element,s=this.options,a=i.find("img");if(0===a.length)throw new Error("Image not defined");switch(p.isValue(i.attr("id"))||i.attr("id",p.elementId("image-magnifier")),i.addClass("image-magnifier").css({width:s.width}).addClass(s.clsMagnifier),t=i.width(),s.height){case"16/9":case"21/9":case"4/3":n=p.aspectRatioH(t,s.height);break;case"auto":n=p.aspectRatioH(t,"16/9");break;default:n=s.height}i.css({height:n});var o=t/2-s.lensSize/2,r=n/2-s.lensSize/2;if("glass"===s.magnifierMode)(e=h("<div>").addClass("image-magnifier-glass").appendTo(i)).css({width:s.lensSize,height:s.lensSize,borderRadius:"circle"!==s.lensType?0:"50%",top:r,left:o,backgroundImage:"url("+a[0].src+")",backgroundRepeat:"no-repeat",backgroundPosition:"-"+(o*s.magnifierZoom-s.lensSize/4+4)+"px -"+(r*s.magnifierZoom-s.lensSize/4+4)+"px",backgroundSize:a[0].width*s.magnifierZoom+"px "+a[0].height*s.magnifierZoom+"px"}).addClass(s.clsLens);else{(e=h("<div>").addClass("image-magnifier-glass").appendTo(i)).css({width:s.lensSize,height:s.lensSize,borderRadius:0,borderWidth:1,top:r,left:o}).addClass(s.clsLens),p.isValue(s.magnifierZoomElement)&&0!==h(s.magnifierZoomElement).length?this.zoomElement=h(s.magnifierZoomElement):this.zoomElement=h("<div>").insertAfter(i);var l=e[0].offsetWidth*s.magnifierZoom,c=e[0].offsetHeight*s.magnifierZoom,d=l/s.lensSize,u=c/s.lensSize;this.zoomElement.css({width:l,height:c,backgroundImage:"url("+a[0].src+")",backgroundRepeat:"no-repeat",backgroundPosition:"-"+o*d+"px -"+r*u+"px",backgroundSize:a[0].width*d+"px "+a[0].height*u+"px"}).addClass(s.clsZoom)}},_createEvents:function(){var s,a,n=this.element,o=this.options,r=n.find(".image-magnifier-glass"),l=r[0].offsetWidth/2,c=n.find("img")[0],d=this.zoomElement;h(window).on(t.events.resize,function(){var e=n.width()/2-o.lensSize/2,t=n.height()/2-o.lensSize/2;"glass"===o.magnifierMode&&r.css({backgroundPosition:"-"+(e*o.magnifierZoom-o.lensSize/4+4)+"px -"+(t*o.magnifierZoom-o.lensSize/4+4)+"px",backgroundSize:c.width*o.magnifierZoom+"px "+c.height*o.magnifierZoom+"px"})},{ns:this.id}),"glass"!==o.magnifierMode&&(s=d[0].offsetWidth/l/2,a=d[0].offsetHeight/l/2,d.css({backgroundSize:c.width*s+"px "+c.height*a+"px"}));function i(e){var t,n,i=parseInt(o.magnifierZoom);"glass"===o.magnifierMode?(t=e.x,n=e.y,t>c.width-l/i&&(t=c.width-l/i),t<l/i&&(t=l/i),n>c.height-l/i&&(n=c.height-l/i),n<l/i&&(n=l/i),r.css({top:n-l,left:t-l,backgroundPosition:"-"+(t*i-l+4)+"px -"+(n*i-l+4)+"px"})):(t=e.x-l,n=e.y-l,t>c.width-2*l&&(t=c.width-2*l),t<0&&(t=0),n>c.height-2*l&&(n=c.height-2*l),n<0&&(n=0),r.css({top:n,left:t}),d.css({backgroundPosition:"-"+t*s+"px -"+n*a+"px"}))}n.on(t.events.move,function(e){var t=p.getCursorPosition(c,e);i(t),p.exec(o.onMagnifierMove,[t,r[0],d?d[0]:void 0],n[0]),n.fire("magnifiermove",{pos:t,glass:r[0],zoomElement:d?d[0]:void 0}),e.preventDefault()}),n.on(t.events.leave,function(){var e=n.width()/2-o.lensSize/2,t=n.height()/2-o.lensSize/2;r.animate({draw:{top:t,left:e}}),i({x:e+o.lensSize/2,y:t+o.lensSize/2})})},changeAttribute:function(e){},destroy:function(){var e=this.element;return e.off(t.events.move),e.off(t.events.leave),e}})}(Metro,m4q),function(c,s){"use strict";var d=c.utils,n={infoboxDeferred:0,type:"",width:480,height:"auto",overlay:!0,overlayColor:"#000000",overlayAlpha:.5,autoHide:0,removeOnClose:!1,closeButton:!0,clsBox:"",clsBoxContent:"",clsOverlay:"",onOpen:c.noop,onClose:c.noop,onInfoBoxCreate:c.noop};c.infoBoxSetup=function(e){n=s.extend({},n,e)},window.metroInfoBoxSetup,c.infoBoxSetup(window.metroInfoBoxSetup),c.Component("info-box",{init:function(e,t){return this._super(t,e,n,{overlay:null,id:d.elementId("info-box")}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("info-box-create",{element:e})},_overlay:function(){var e=this.options,t=s("<div>");return t.addClass("overlay").addClass(e.clsOverlay),"transparent"===e.overlayColor?t.addClass("transparent"):t.css({background:d.hex2rgba(e.overlayColor,e.overlayAlpha)}),t},_createStructure:function(){var e,t,n=this.element,i=this.options;!0===i.overlay&&(this.overlay=this._overlay()),n.addClass("info-box").addClass(i.type).addClass(i.clsBox),0===(e=n.find("closer")).length&&(e=s("<span>").addClass("button square closer")).appendTo(n),!0!==i.closeButton&&e.hide(),0<(t=n.find(".info-box-content")).length&&t.addClass(i.clsBoxContent),n.css({width:i.width,height:i.height,visibility:"hidden",top:"100%",left:(s(window).width()-n.outerWidth())/2}),n.appendTo(s("body"))},_createEvents:function(){var e=this,t=this.element;t.on(c.events.click,".closer",function(){e.close()}),t.on(c.events.click,".js-dialog-close",function(){e.close()}),s(window).on(c.events.resize,function(){e.reposition()},{ns:this.id})},_setPosition:function(){var e=this.element;e.css({top:(s(window).height()-e.outerHeight())/2,left:(s(window).width()-e.outerWidth())/2})},reposition:function(){this._setPosition()},setContent:function(e){var t=this.element.find(".info-box-content");0!==t.length&&(t.html(e),this.reposition())},setType:function(e){this.element.removeClass("success info alert warning").addClass(e)},open:function(){var e=this,t=this.element,n=this.options;!0===n.overlay&&this.overlay.appendTo(s("body")),this._setPosition(),t.css({visibility:"visible"}),d.exec(n.onOpen,null,t[0]),t.fire("open"),t.data("open",!0),0<parseInt(n.autoHide)&&setTimeout(function(){e.close()},parseInt(n.autoHide))},close:function(){var e=this.element,t=this.options;!0===t.overlay&&s("body").find(".overlay").remove(),e.css({visibility:"hidden",top:"100%"}),d.exec(t.onClose,null,e[0]),e.fire("close"),e.data("open",!1),!0===t.removeOnClose&&(this.destroy(),e.remove())},isOpen:function(){return!0===this.element.data("open")},changeAttribute:function(e){},destroy:function(){var e=this.element;return e.off("all"),s(window).off(c.events.resize,{ns:this.id}),e}}),c.infobox={isInfoBox:function(e){return d.isMetroObject(e,"infobox")},open:function(e,t,n){if(!this.isInfoBox(e))return!1;var i=c.getPlugin(e,"infobox");void 0!==t&&i.setContent(t),void 0!==n&&i.setType(n),i.open()},close:function(e){if(!this.isInfoBox(e))return!1;c.getPlugin(e,"infobox").close()},setContent:function(e,t){if(!this.isInfoBox(e))return!1;void 0===t&&(t="");var n=c.getPlugin(e,"infobox");n.setContent(t),n.reposition()},setType:function(e,t){if(!this.isInfoBox(e))return!1;var n=c.getPlugin(e,"infobox");n.setType(t),n.reposition()},isOpen:function(e){return!!this.isInfoBox(e)&&c.getPlugin(e,"infobox").isOpen()},create:function(e,t,n,i){var s,a,o,r=d.$();o=void 0!==t?t:"",s=r("<div>").appendTo(r("body")),r("<div>").addClass("info-box-content").appendTo(s);var l=r.extend({},{removeOnClose:!0,type:o},void 0!==n?n:{});return l._runtime=!0,s.infobox(l),(a=c.getPlugin(s,"infobox")).setContent(e),!1!==i&&a.open(),s}}}(Metro,m4q),function(e,i){"use strict";var s=e.utils,n={materialinputDeferred:0,label:"",informer:"",icon:"",permanentLabel:!1,clsComponent:"",clsInput:"",clsLabel:"",clsInformer:"",clsIcon:"",clsLine:"",onInputCreate:e.noop};e.materialInputSetup=function(e){n=i.extend({},n,e)},window.metroMaterialInputSetup,e.materialInputSetup(window.metroMaterialInputSetup),e.Component("material-input",{init:function(e,t){return this._super(t,e,n,{history:[],historyIndex:-1}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("input-create",{element:e})},_createStructure:function(){var e=this.element,t=this.options,n=i("<div>").addClass("input-material "+e[0].className);e[0].className="",e.attr("autocomplete","nope"),void 0===e.attr("type")&&e.attr("type","text"),n.insertBefore(e),e.appendTo(n),s.isValue(t.label)&&i("<span>").html(t.label).addClass("label").addClass(t.clsLabel).insertAfter(e),s.isValue(t.informer)&&i("<span>").html(t.informer).addClass("informer").addClass(t.clsInformer).insertAfter(e),s.isValue(t.icon)&&(n.addClass("with-icon"),i("<span>").html(t.icon).addClass("icon").addClass(t.clsIcon).insertAfter(e)),n.append(i("<hr>").addClass(t.clsLine)),!0===t.permanentLabel&&n.addClass("permanent-label"),n.addClass(t.clsComponent),e.addClass(t.clsInput),e.is(":disabled")?this.disable():this.enable()},_createEvents:function(){},clear:function(){this.element.val("")},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},changeAttribute:function(e){"disabled"===e&&this.toggleState()},destroy:function(){return this.element}})}(Metro,m4q),function(a,l){"use strict";var c=a.utils,n={inputDeferred:0,autocomplete:null,autocompleteDivider:",",autocompleteListHeight:200,history:!1,historyPreset:"",historyDivider:"|",preventSubmit:!1,defaultValue:"",size:"default",prepend:"",append:"",copyInlineStyles:!1,searchButton:!1,clearButton:!0,revealButton:!0,clearButtonIcon:"<span class='default-icon-cross'></span>",revealButtonIcon:"<span class='default-icon-eye'></span>",searchButtonIcon:"<span class='default-icon-search'></span>",customButtons:[],searchButtonClick:"submit",clsComponent:"",clsInput:"",clsPrepend:"",clsAppend:"",clsClearButton:"",clsRevealButton:"",clsCustomButton:"",clsSearchButton:"",onHistoryChange:a.noop,onHistoryUp:a.noop,onHistoryDown:a.noop,onClearClick:a.noop,onRevealClick:a.noop,onSearchButtonClick:a.noop,onEnterClick:a.noop,onInputCreate:a.noop};a.inputSetup=function(e){n=l.extend({},n,e)},window.metroInputSetup,a.inputSetup(window.metroInputSetup),a.Component("input",{init:function(e,t){return this._super(t,e,n,{history:[],historyIndex:-1,autocomplete:[]}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("input-create",{element:e})},_createStructure:function(){var e=this,t=this.element,n=this.options,i=l("<div>").addClass("input "+t[0].className),s=l("<div>").addClass("button-group");c.isValue(n.historyPreset)&&(l.each(n.historyPreset.toArray(n.historyDivider),function(){e.history.push(this)}),e.historyIndex=e.history.length-1),void 0===t.attr("type")&&t.attr("type","text"),i.insertBefore(t),t.appendTo(i),s.appendTo(i),c.isValue(t.val().trim())||t.val(n.defaultValue),!0!==n.clearButton||t[0].readOnly||l("<button>").addClass("button input-clear-button").addClass(n.clsClearButton).attr("tabindex",-1).attr("type","button").html(n.clearButtonIcon).appendTo(s),"password"===t.attr("type")&&!0===n.revealButton&&l("<button>").addClass("button input-reveal-button").addClass(n.clsRevealButton).attr("tabindex",-1).attr("type","button").html(n.revealButtonIcon).appendTo(s),!0===n.searchButton&&l("<button>").addClass("button input-search-button").addClass(n.clsSearchButton).attr("tabindex",-1).attr("type","submit"===n.searchButtonClick?"submit":"button").html(n.searchButtonIcon).appendTo(s),c.isValue(n.prepend)&&l("<div>").html(n.prepend).addClass("prepend").addClass(n.clsPrepend).appendTo(i);c.isValue(n.append)&&l("<div>").html(n.append).addClass("append").addClass(n.clsAppend).appendTo(i);if("string"==typeof n.customButtons&&(n.customButtons=c.isObject(n.customButtons)),"object"==typeof n.customButtons&&0<c.objectLength(n.customButtons)&&l.each(n.customButtons,function(){var e=l("<button>");e.addClass("button input-custom-button").addClass(n.clsCustomButton).addClass(this.cls).attr("tabindex",-1).attr("type","button").html(this.html),e.data("action",this.onclick),e.appendTo(s)}),c.isValue(t.attr("data-exclaim"))&&i.attr("data-exclaim",t.attr("data-exclaim")),"rtl"===t.attr("dir")&&i.addClass("rtl").attr("dir","rtl"),!(t[0].className="")===n.copyInlineStyles)for(var a=0,o=t[0].style.length;a<o;a++)i.css(t[0].style[a],t.css(t[0].style[a]));if(i.addClass(n.clsComponent),t.addClass(n.clsInput),"default"!==n.size&&i.css({width:n.size}),!c.isNull(n.autocomplete)){var r=c.isObject(n.autocomplete);this.autocomplete=!1!==r?r:n.autocomplete.toArray(n.autocompleteDivider),l("<div>").addClass("autocomplete-list").css({maxHeight:n.autocompleteListHeight,display:"none"}).appendTo(i)}t.is(":disabled")?this.disable():this.enable()},_createEvents:function(){var n=this,i=this.element,s=this.options,e=i.closest(".input"),o=e.find(".autocomplete-list");e.on(a.events.click,".input-clear-button",function(){var e=i.val();i.val(c.isValue(s.defaultValue)?s.defaultValue:"").fire("clear").fire("change").fire("keyup").focus(),0<o.length&&o.css({display:"none"}),c.exec(s.onClearClick,[e,i.val()],i[0]),i.fire("clearclick",{prev:e,val:i.val()})}),e.on(a.events.click,".input-reveal-button",function(){"password"===i.attr("type")?i.attr("type","text"):i.attr("type","password"),c.exec(s.onRevealClick,[i.val()],i[0]),i.fire("revealclick",{val:i.val()})}),e.on(a.events.click,".input-search-button",function(){"submit"!==s.searchButtonClick?(c.exec(s.onSearchButtonClick,[i.val()],this),i.fire("searchbuttonclick",{val:i.val(),button:this})):this.form.submit()}),e.on(a.events.click,".input-custom-button",function(){var e=l(this),t=e.data("action");c.exec(t,[i.val(),e],this)}),i.on(a.events.keyup,function(e){var t=i.val().trim();s.history&&e.keyCode===a.keyCode.ENTER&&""!==t&&(i.val(""),n.history.push(t),n.historyIndex=n.history.length-1,c.exec(s.onHistoryChange,[t,n.history,n.historyIndex],i[0]),i.fire("historychange",{val:t,history:n.history,historyIndex:n.historyIndex}),!0===s.preventSubmit&&e.preventDefault()),s.history&&e.keyCode===a.keyCode.UP_ARROW&&(n.historyIndex--,0<=n.historyIndex?(i.val(""),i.val(n.history[n.historyIndex]),c.exec(s.onHistoryDown,[i.val(),n.history,n.historyIndex],i[0]),i.fire("historydown",{val:i.val(),history:n.history,historyIndex:n.historyIndex})):n.historyIndex=0,e.preventDefault()),s.history&&e.keyCode===a.keyCode.DOWN_ARROW&&(n.historyIndex++,n.historyIndex<n.history.length?(i.val(""),i.val(n.history[n.historyIndex]),c.exec(s.onHistoryUp,[i.val(),n.history,n.historyIndex],i[0]),i.fire("historyup",{val:i.val(),history:n.history,historyIndex:n.historyIndex})):n.historyIndex=n.history.length-1,e.preventDefault())}),i.on(a.events.keydown,function(e){e.keyCode===a.keyCode.ENTER&&(c.exec(s.onEnterClick,[i.val()],i[0]),i.fire("enterclick",{val:i.val()}))}),i.on(a.events.blur,function(){e.removeClass("focused")}),i.on(a.events.focus,function(){e.addClass("focused")}),i.on(a.events.input,function(){var e,a=this.value.toLowerCase();0!==o.length&&(o.html(""),e=n.autocomplete.filter(function(e){return-1<e.toLowerCase().indexOf(a)}),o.css({display:0<e.length?"block":"none"}),l.each(e,function(e,t){var n,i=t.toLowerCase().indexOf(a),s=l("<div>").addClass("item").attr("data-autocomplete-value",t);n=0===i?"<strong>"+t.substr(0,a.length)+"</strong>"+t.substr(a.length):t.substr(0,i)+"<strong>"+t.substr(i,a.length)+"</strong>"+t.substr(i+a.length),s.html(n).appendTo(o)}))}),e.on(a.events.click,".autocomplete-list .item",function(){i.val(l(this).attr("data-autocomplete-value")),o.css({display:"none"}),i.trigger("change")})},getHistory:function(){return this.history},getHistoryIndex:function(){return this.historyIndex},setHistoryIndex:function(e){this.historyIndex=e>=this.history.length?this.history.length-1:e},setHistory:function(e,t){var n=this,i=this.options;c.isNull(e)||(Array.isArray(e)||"string"!=typeof e||(e=e.toArray(i.historyDivider)),!0===t?l.each(e,function(){n.history.push(this)}):this.history=e,this.historyIndex=this.history.length-1)},clear:function(){this.element.val("")},toDefault:function(){this.element.val(c.isValue(this.options.defaultValue)?this.options.defaultValue:"")},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},setAutocompleteList:function(e){var t=c.isObject(e);!1!==t?this.autocomplete=t:"string"==typeof e&&(this.autocomplete=e.toArray(this.options.autocompleteDivider))},changeAttribute:function(e){switch(e){case"disabled":this.toggleState()}},destroy:function(){var e=this.element,t=e.parent(),n=t.find(".input-clear-button"),i=t.find(".input-reveal-button"),s=t.find(".input-custom-button");return 0<n.length&&n.off(a.events.click),0<i.length&&(i.off(a.events.start),i.off(a.events.stop)),0<s.length&&n.off(a.events.click),e.off(a.events.blur),e.off(a.events.focus),e}}),l(document).on(a.events.click,function(){l(".input .autocomplete-list").hide()})}(Metro,m4q),function(r,l){"use strict";var a=r.utils,n={keypadDeferred:0,keySize:48,keys:"1, 2, 3, 4, 5, 6, 7, 8, 9, 0",copyInlineStyles:!1,target:null,keyLength:0,shuffle:!1,shuffleCount:3,position:r.position.BOTTOM_LEFT,dynamicPosition:!1,serviceButtons:!0,showValue:!0,open:!1,sizeAsKeys:!1,clsKeypad:"",clsInput:"",clsKeys:"",clsKey:"",clsServiceKey:"",clsBackspace:"",clsClear:"",onChange:r.noop,onClear:r.noop,onBackspace:r.noop,onShuffle:r.noop,onKey:r.noop,onKeypadCreate:r.noop};r.keypadSetup=function(e){n=l.extend({},n,e)},window.metroKeypadSetup,r.keypadSetup(window.metroKeypadSetup),r.Component("keypad",{init:function(e,t){return this._super(t,e,n,{value:"INPUT"===t.tagName?t.value:t.innerText,positions:["top-left","top","top-right","right","bottom-right","bottom","bottom-left","left"],keypad:null,keys:[],keys_to_work:[]}),this},_create:function(){var e=this.element,t=this.options;this.keys=t.keys.toArray(","),this.keys_to_work=this.keys,this._createKeypad(),!0===t.shuffle&&this.shuffle(),this._createKeys(),this._createEvents(),this._fireEvent("keypad-create",{element:e})},_createKeypad:function(){var e,t,n=this.element,i=this.options,s=n.parent();if((e=s.hasClass("input")?s:l("<div>").addClass("input").addClass(n[0].className)).addClass("keypad"),"static"!==e.css("position")&&""!==e.css("position")||e.css({position:"relative"}),void 0===n.attr("type")&&n.attr("type","text"),e.insertBefore(n),n.attr("readonly",!0),n.appendTo(e),(t=l("<div>").addClass("keys").addClass(i.clsKeys)).appendTo(e),this._setKeysPosition(),!0===i.open&&t.addClass("open keep-open"),!(n[0].className="")===i.copyInlineStyles)for(var a=0,o=n[0].style.length;a<o;a++)e.css(n[0].style[a],n.css(n[0].style[a]));n.addClass(i.clsInput),e.addClass(i.clsKeypad),n.on(r.events.blur,function(){e.removeClass("focused")}),n.on(r.events.focus,function(){e.addClass("focused")}),!0===i.disabled||n.is(":disabled")?this.disable():this.enable(),this.keypad=e},_setKeysPosition:function(){var e=this.element,t=this.options;e.parent().find(".keys").removeClass(this.positions.join(" ")).addClass(t.position)},_createKeys:function(){var e,t,n=this.element,i=this.options,s=n.parent(),a=s.find(".keys"),o=Math.round(Math.sqrt(this.keys.length+2)),r=i.keySize;if(a.html(""),l.each(this.keys_to_work,function(){(e=l("<span>").addClass("key").addClass(i.clsKey).html(this)).data("key",this),e.css({width:i.keySize,height:i.keySize,lineHeight:i.keySize-4}).appendTo(a)}),!0===i.serviceButtons){l.each(["&larr;","&times;"],function(){e=l("<span>").addClass("key service-key").addClass(i.clsKey).addClass(i.clsServiceKey).html(this),"&larr;"===this&&e.addClass(i.clsBackspace),"&times;"===this&&e.addClass(i.clsClear),e.data("key",this),e.css({width:i.keySize,height:i.keySize,lineHeight:i.keySize-4}).appendTo(a)})}t=o*(r+2)-6,a.outerWidth(t),!0===i.sizeAsKeys&&-1!==["top-left","top","top-right","bottom-left","bottom","bottom-right"].indexOf(i.position)&&s.outerWidth(a.outerWidth())},_createEvents:function(){var n=this,i=this.element,s=this.options,e=i.parent(),t=e.find(".keys");t.on(r.events.click,".key",function(e){var t=l(this);if("&larr;"!==t.data("key")&&"&times;"!==t.data("key")){if(0<s.keyLength&&String(n.value).length===s.keyLength)return!1;n.value=n.value+""+t.data("key"),!0===s.shuffle&&(n.shuffle(),n._createKeys()),!0===s.dynamicPosition&&(s.position=n.positions[l.random(0,n.positions.length-1)],n._setKeysPosition()),a.exec(s.onKey,[t.data("key"),n.value],i[0]),i.fire("key",{key:t.data("key"),val:n.value})}else"&times;"===t.data("key")&&(n.value="",a.exec(s.onClear,null,i[0]),i.fire("clear")),"&larr;"===t.data("key")&&(n.value=n.value.substring(0,n.value.length-1),a.exec(s.onBackspace,[n.value],i[0]),i.fire("backspace"));!0===s.showValue&&("INPUT"===i[0].tagName?i.val(n.value):i.text(n.value)),i.trigger("change"),a.exec(s.onChange,[n.value],i[0]),e.preventDefault(),e.stopPropagation()}),e.on(r.events.click,function(e){!0!==s.open&&(!0===t.hasClass("open")?t.removeClass("open"):t.addClass("open"),e.preventDefault(),e.stopPropagation())}),null!==s.target&&i.on(r.events.change,function(){var e=l(s.target);0!==e.length&&("INPUT"===e[0].tagName?e.val(n.value):e.text(n.value))})},shuffle:function(){for(var e=this.element,t=this.options,n=0;n<t.shuffleCount;n++)this.keys_to_work=this.keys_to_work.shuffle();a.exec(t.onShuffle,[this.keys_to_work,this.keys],e[0]),e.fire("shuffle",{keys:this.keys,keysToWork:this.keys_to_work})},shuffleKeys:function(e){void 0===e&&(e=this.options.shuffleCount);for(var t=0;t<e;t++)this.keys_to_work=this.keys_to_work.shuffle();this._createKeys()},val:function(e){return void 0===e?this.value:(this.value=e,"INPUT"===this.element[0].tagName?this.element.val(e):this.element.text(e),this)},open:function(){this.element.parent().find(".keys").addClass("open")},close:function(){this.element.parent().find(".keys").removeClass("open")},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},setPosition:function(e){var t=void 0!==e?e:this.element.attr("data-position");-1!==this.positions.indexOf(t)&&(this.options.position=t,this._setKeysPosition())},changeAttribute:function(e){switch(e){case"disabled":this.toggleState();break;case"data-position":this.setPosition()}},destroy:function(){var e=this.element,t=this.keypad,n=t.find(".keys");return t.off(r.events.click),n.off(r.events.click,".key"),e.off(r.events.change),e}}),l(document).on(r.events.click,function(){var e=l(".keypad .keys");l.each(e,function(){l(this).hasClass("keep-open")||l(this).removeClass("open")})})}(Metro,m4q),function(s,c){"use strict";var d=s.utils,n={listDeferred:0,templateBeginToken:"<%",templateEndToken:"%>",paginationDistance:5,paginationShortMode:!0,thousandSeparator:",",decimalSeparator:",",sortTarget:"li",sortClass:null,sortDir:"asc",sortInitial:!0,filterClass:null,filter:null,filterString:"",filters:null,source:null,showItemsSteps:!1,showSearch:!1,showListInfo:!1,showPagination:!1,showActivity:!0,muteList:!0,items:-1,itemsSteps:"all, 10,25,50,100",itemsAllTitle:"Show all",listItemsCountTitle:"Show entries:",listSearchTitle:"Search:",listInfoTitle:"Showing $1 to $2 of $3 entries",paginationPrevTitle:"Prev",paginationNextTitle:"Next",activityType:"cycle",activityStyle:"color",activityTimeout:100,searchWrapper:null,rowsWrapper:null,infoWrapper:null,paginationWrapper:null,clsComponent:"",clsList:"",clsListItem:"",clsListTop:"",clsItemsCount:"",clsSearch:"",clsListBottom:"",clsListInfo:"",clsListPagination:"",clsPagination:"",onDraw:s.noop,onDrawItem:s.noop,onSortStart:s.noop,onSortStop:s.noop,onSortItemSwitch:s.noop,onSearch:s.noop,onRowsCountChange:s.noop,onDataLoad:s.noop,onDataLoaded:s.noop,onDataLoadError:s.noop,onFilterItemAccepted:s.noop,onFilterItemDeclined:s.noop,onListCreate:s.noop};s.listSetup=function(e){n=c.extend({},n,e)},window.metroListSetup,s.listSetup(window.metroListSetup),s.Component("list",{init:function(e,t){return this._super(t,e,n,{currentPage:1,pagesCount:1,filterString:"",data:null,activity:null,busy:!1,filters:[],wrapperInfo:null,wrapperSearch:null,wrapperRows:null,wrapperPagination:null,filterIndex:null,filtersIndexes:[],itemTemplate:null,sort:{dir:"asc",colIndex:0},header:null,items:[]}),this},_create:function(){var t=this,n=this.options;n.source?(t._fireEvent("data-load",{source:n.source}),c.json(n.source).then(function(e){t._fireEvent("data-loaded",{source:n.source,data:e}),t._build(e)},function(e){t._fireEvent("data-load-error",{source:n.source,xhr:e})})):t._build()},_build:function(e){var t=this.element,n=this.options;d.isValue(e)?this._createItemsFromJSON(e):this._createItemsFromHTML(),this._createStructure(),this._createEvents(),d.exec(n.onListCreate,[t],t[0]),t.fire("listcreate")},_createItemsFromHTML:function(){var e=this,t=this.element,n=this.options;this.items=[],c.each(t.children(n.sortTarget),function(){e.items.push(this)})},_createItemsFromJSON:function(e){var n=this,i=this.options;this.items=[],d.isValue(e.template)&&(this.itemTemplate=e.template),d.isValue(e.header)&&(this.header=e.header),d.isValue(e.data)&&c.each(e.data,function(){var e,t=document.createElement("li");d.isValue(n.itemTemplate)&&(e=s.template(n.itemTemplate,this,{beginToken:i.templateBeginToken,endToken:i.templateEndToken}),t.innerHTML=e,n.items.push(t))})},_createTopBlock:function(){var e,t,n,i=this,s=this.element,a=this.options,o=c("<div>").addClass("list-top").addClass(a.clsListTop).insertBefore(s);return e=d.isValue(this.wrapperSearch)?this.wrapperSearch:c("<div>").addClass("list-search-block").addClass(a.clsSearch).appendTo(o),c("<input>").attr("type","text").appendTo(e).input({prepend:a.listSearchTitle}),!0!==a.showSearch&&e.hide(),t=d.isValue(this.wrapperRows)?this.wrapperRows:c("<div>").addClass("list-rows-block").addClass(a.clsItemsCount).appendTo(o),n=c("<select>").appendTo(t),c.each(a.itemsSteps.toArray(),function(){var e=c("<option>").attr("value","all"===this?-1:this).text("all"===this?a.itemsAllTitle:this).appendTo(n);parseInt(this)===parseInt(a.items)&&e.attr("selected","selected")}),n.select({filter:!1,prepend:a.listItemsCountTitle,onChange:function(e){parseInt(e)!==parseInt(a.items)&&(a.items=parseInt(e),i.currentPage=1,i._draw(),d.exec(a.onRowsCountChange,[e],s[0]),s.fire("rowscountchange",{val:e}))}}),!0!==a.showItemsSteps&&t.hide(),o},_createBottomBlock:function(){var e,t,n=this.element,i=this.options,s=c("<div>").addClass("list-bottom").addClass(i.clsListBottom).insertAfter(n);return e=c("<div>").addClass("list-info").addClass(i.clsListInfo).appendTo(s),!0!==i.showListInfo&&e.hide(),t=c("<div>").addClass("list-pagination").addClass(i.clsListPagination).appendTo(s),!0!==i.showPagination&&t.hide(),s},_createStructure:function(){var e,t,n=this,i=this.element,s=this.options,a=c(s.searchWrapper),o=c(s.infoWrapper),r=c(s.rowsWrapper),l=c(s.paginationWrapper);0<a.length&&(this.wrapperSearch=a),0<o.length&&(this.wrapperInfo=o),0<r.length&&(this.wrapperRows=r),0<l.length&&(this.wrapperPagination=l),i.parent().hasClass("list-component")?e=i.parent():(e=c("<div>").addClass("list-component").insertBefore(i),i.appendTo(e)),e.addClass(s.clsComponent),this.activity=c("<div>").addClass("list-progress").appendTo(e),c("<div>").activity({type:s.activityType,style:s.activityStyle}).appendTo(this.activity),!0!==s.showActivity&&this.activity.css({visibility:"hidden"}),i.addClass(s.clsList),this._createTopBlock(),this._createBottomBlock(),d.isValue(s.filterString)&&(this.filterString=s.filterString),d.isValue(s.filter)&&(!1===(t=d.isFunc(s.filter))&&(t=d.func(s.filter)),n.filterIndex=n.addFilter(t)),d.isValue(s.filters)&&"string"==typeof s.filters&&c.each(s.filters.toArray(),function(){!1!==(t=d.isFunc(this))&&n.filtersIndexes.push(n.addFilter(t))}),!(this.currentPage=1)!==s.sortInitial?this.sorting(s.sortClass,s.sortDir,!0):this.draw()},_createEvents:function(){var e,i=this,t=this.element.parent();function n(e){var t=c(e),n=t.parent();n.hasClass("active")||(n.hasClass("service")?"prev"===t.data("page")?(i.currentPage--,0===i.currentPage&&(i.currentPage=1)):(i.currentPage++,i.currentPage>i.pagesCount&&(i.currentPage=i.pagesCount)):i.currentPage=t.data("page"),i._draw())}t.find(".list-search-block input").on(s.events.inputchange,function(){i.filterString=this.value.trim().toLowerCase(),":"!==i.filterString[i.filterString.length-1]&&(i.currentPage=1,i._draw())}),d.isValue(this.wrapperSearch)&&0<(e=this.wrapperSearch.find("input")).length&&e.on(s.events.inputchange,function(){i.filterString=this.value.trim().toLowerCase(),":"!==i.filterString[i.filterString.length-1]&&(i.currentPage=1,i._draw())}),t.on(s.events.click,".pagination .page-link",function(){n(this)}),d.isValue(this.wrapperPagination)&&this.wrapperPagination.on(s.events.click,".pagination .page-link",function(){n(this)})},_info:function(e,t,n){var i,s=this.element,a=this.options,o=s.parent(),r=d.isValue(this.wrapperInfo)?this.wrapperInfo:o.find(".list-info");0!==r.length&&(n<t&&(t=n),0===this.items.length&&(e=t=n=0),i=(i=(i=(i=a.listInfoTitle).replace("$1",e)).replace("$2",t)).replace("$3",n),r.html(i))},_paging:function(e){var t=this.element,n=this.options,i=t.parent();this.pagesCount=Math.ceil(e/n.items),s.pagination({length:e,rows:n.items,current:this.currentPage,target:d.isValue(this.wrapperPagination)?this.wrapperPagination:i.find(".list-pagination"),claPagination:n.clsPagination,prevTitle:n.paginationPrevTitle,nextTitle:n.paginationNextTitle,distance:!0===n.paginationShortMode?n.paginationDistance:0})},_filter:function(){var e,t,n,i,s,a,o=this,r=this.element,l=this.options;return d.isValue(this.filterString)||0<this.filters.length?(e=this.items.filter(function(e){if(n="",d.isValue(l.filterClass)){if(0<(i=e.getElementsByClassName(l.filterClass)).length)for(t=0;t<i.length;t++)n+=i[t].textContent}else n=e.textContent;if(s=n.replace(/[\n\r]+|[\s]{2,}/g," ").trim().toLowerCase(),!0===(a=!d.isValue(o.filterString)||-1<s.indexOf(o.filterString))&&0<o.filters.length)for(t=0;t<o.filters.length;t++)if(!0!==d.exec(o.filters[t],[e])){a=!1;break}return a?(d.exec(l.onFilterItemAccepted,[e],r[0]),r.fire("filteritemaccepted",{item:e})):(d.exec(l.onFilterItemDeclined,[e],r[0]),r.fire("filteritemdeclined",{item:e})),a}),d.exec(l.onSearch,[o.filterString,e],r[0]),r.fire("search",{search:o.filterString,items:e})):e=this.items,e},_draw:function(e){var t,n,i=this.element,s=this.options,a=-1===s.items?0:s.items*(this.currentPage-1),o=-1===s.items?this.items.length-1:a+s.items-1;for(n=this._filter(),i.children(s.sortTarget).remove(),t=a;t<=o;t++)d.isValue(n[t])&&c(n[t]).addClass(s.clsListItem).appendTo(i),d.exec(s.onDrawItem,[n[t]],i[0]),i.fire("drawitem",{item:n[t]});this._info(1+a,1+o,n.length),this._paging(n.length),this.activity.hide(),d.exec(s.onDraw,null,i[0]),i.fire("draw"),void 0!==e&&d.exec(e,[i],i[0])},_getItemContent:function(e){var t,n,i,s,a=this.options,o=c(e),r=d.isValue(o.data("formatMask"))?o.data("formatMask"):null;if(d.isValue(a.sortClass)){if(i="",0<(n=c(e).find("."+a.sortClass)).length)for(t=0;t<n.length;t++)i+=n[t].textContent;s=0<n.length?n[0].getAttribute("data-format"):""}else i=e.textContent,s=e.getAttribute("data-format");if(i=(""+i).toLowerCase().replace(/[\n\r]+|[\s]{2,}/g," ").trim(),d.isValue(s))switch(-1===["number","int","integer","float","money"].indexOf(s)||","===a.thousandSeparator&&"."===a.decimalSeparator||(i=d.parseNumber(i,a.thousandSeparator,a.decimalSeparator)),s){case"date":i=d.isValue(r)?i.toDate(r):new Date(i);break;case"number":i=Number(i);break;case"int":case"integer":i=parseInt(i);break;case"float":i=parseFloat(i);break;case"money":i=d.parseMoney(i);break;case"card":i=d.parseCard(i);break;case"phone":i=d.parsePhone(i)}return i},deleteItem:function(e){var t,n,i=[],s=d.isFunc(e);for(t=0;t<this.items.length;t++)n=this.items[t],s?d.exec(e,[n])&&i.push(t):n.textContent.contains(e)&&i.push(t);return this.items=d.arrayDeleteByMultipleKeys(this.items,i),this},draw:function(){return this._draw()},sorting:function(e,t,n){var a=this,o=this.element,r=this.options;return d.isValue(e)&&(r.sortClass=e),d.isValue(t)&&-1<["asc","desc"].indexOf(t)&&(r.sortDir=t),d.exec(r.onSortStart,[this.items],o[0]),o.fire("sortstart",{items:this.items}),this.items.sort(function(e,t){var n=a._getItemContent(e),i=a._getItemContent(t),s=0;return n<i&&(s="asc"===r.sortDir?-1:1),i<n&&(s="asc"===r.sortDir?1:-1),0!==s&&(d.exec(r.onSortItemSwitch,[e,t,s],o[0]),o.fire("sortitemswitch",{a:e,b:t,result:s})),s}),d.exec(r.onSortStop,[this.items],o[0]),o.fire("sortstop",{items:this.items}),!0===n&&this._draw(),this},filter:function(e){this.filterString=e.trim().toLowerCase(),this.currentPage=1,this._draw()},loadData:function(e){var n=this,i=this.element,s=this.options;!0===d.isValue(e)&&(s.source=e,d.exec(s.onDataLoad,[s.source],i[0]),i.fire("dataload",{source:s.source}),c.json(s.source).then(function(e){var t;d.exec(s.onDataLoaded,[s.source,e],i[0]),i.fire("dataloaded",{source:s.source,data:e}),n._createItemsFromJSON(e),i.html(""),d.isValue(s.filterString)&&(n.filterString=s.filterString),d.isValue(s.filter)&&(!1===(t=d.isFunc(s.filter))&&(t=d.func(s.filter)),n.filterIndex=n.addFilter(t)),d.isValue(s.filters)&&"string"==typeof s.filters&&c.each(s.filters.toArray(),function(){!1!==(t=d.isFunc(this))&&n.filtersIndexes.push(n.addFilter(t))}),n.currentPage=1,n.sorting(s.sortClass,s.sortDir,!0)},function(e){d.exec(s.onDataLoadError,[s.source,e],i[0]),i.fire("dataloaderror",{source:s.source,xhr:e})}))},next:function(){0!==this.items.length&&(this.currentPage++,this.currentPage>this.pagesCount?this.currentPage=this.pagesCount:this._draw())},prev:function(){0!==this.items.length&&(this.currentPage--,0!==this.currentPage?this._draw():this.currentPage=1)},first:function(){0!==this.items.length&&(this.currentPage=1,this._draw())},last:function(){0!==this.items.length&&(this.currentPage=this.pagesCount,this._draw())},page:function(e){e<=0&&(e=1),e>this.pagesCount&&(e=this.pagesCount),this.currentPage=e,this._draw()},addFilter:function(e,t){var n=d.isFunc(e);if(!1!==n)return this.filters.push(n),!0===t&&(this.currentPage=1,this.draw()),this.filters.length-1},removeFilter:function(e,t){return d.arrayDeleteByKey(this.filters,e),!0===t&&(this.currentPage=1,this.draw()),this},removeFilters:function(e){this.filters=[],!0===e&&(this.currentPage=1,this.draw())},getFilters:function(){return this.filters},getFilterIndex:function(){return this.filterIndex},getFiltersIndexes:function(){return this.filtersIndexes},changeAttribute:function(e){var t,n,i,s=this,a=this.element,o=this.options;switch(e){case"data-sort-dir":i=a.attr("data-sort-dir"),d.isValue(i)&&(o.sortDir=i,s.sorting(o.sortClass,o.sortDir,!0));break;case"data-sort-source":n=a.attr("data-sort-source"),d.isValue(n)&&(o.sortClass=n,s.sorting(o.sortClass,o.sortDir,!0));break;case"data-filter-string":t=a.attr("data-filter-string"),d.isValue(t)&&(o.filterString=t,s.filter(o.filterString))}},destroy:function(){var e,t=this.element,n=t.parent();return n.find(".list-search-block input").off(s.events.inputchange),d.isValue(this.wrapperSearch)&&0<(e=this.wrapperSearch.find("input")).length&&e.off(s.events.inputchange),n.off(s.events.click,".pagination .page-link"),d.isValue(this.wrapperPagination)&&this.wrapperPagination.off(s.events.click,".pagination .page-link"),t}})}(Metro,m4q),function(r,l){"use strict";var c=r.utils,n={listviewDeferred:0,selectable:!1,checkStyle:1,duration:100,view:r.listView.LIST,selectCurrent:!0,structure:{},onNodeInsert:r.noop,onNodeDelete:r.noop,onNodeClean:r.noop,onCollapseNode:r.noop,onExpandNode:r.noop,onGroupNodeClick:r.noop,onNodeClick:r.noop,onNodeDblclick:r.noop,onListViewCreate:r.noop};r.listViewSetup=function(e){n=l.extend({},n,e)},window.metroListViewSetup,r.listViewSetup(window.metroListViewSetup),r.Component("listview",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e=this.element;this._createView(),this._createEvents(),this._fireEvent("listview-create",{element:e})},_createIcon:function(e){var t,n;return n=c.isTag(e)?l(e):l("<img>").attr("src",e),(t=l("<span>").addClass("icon")).html(n.outerHTML()),t},_createCaption:function(e){return l("<div>").addClass("caption").html(e)},_createContent:function(e){return l("<div>").addClass("content").html(e)},_createToggle:function(){return l("<span>").addClass("node-toggle")},_createNode:function(n){var i,e=this.options;if(i=l("<li>"),void 0!==n.caption||void 0!==n.content){var t=l("<div>").addClass("data");i.prepend(t),void 0!==n.caption&&t.append(this._createCaption(n.caption)),void 0!==n.content&&t.append(this._createContent(n.content))}return void 0!==n.icon&&i.prepend(this._createIcon(n.icon)),0<c.objectLength(e.structure)&&l.each(e.structure,function(e,t){void 0!==n[e]&&l("<div>").addClass("node-data item-data-"+e).addClass(n[t]).html(n[e]).appendTo(i)}),i},_createView:function(){var i=this,e=this.element,s=this.options,t=e.find("li"),a=c.objectLength(s.structure);e.addClass("listview"),e.find("ul").addClass("listview"),l.each(t,function(){var t=l(this);if(void 0!==t.data("caption")||void 0!==t.data("content")){var e=l("<div>").addClass("data");t.prepend(e),void 0!==t.data("caption")&&e.append(i._createCaption(t.data("caption"))),void 0!==t.data("content")&&e.append(i._createContent(t.data("content")))}if(void 0!==t.data("icon")&&t.prepend(i._createIcon(t.data("icon"))),0<t.children("ul").length?(t.addClass("node-group"),t.append(i._createToggle()),!0!==t.data("collapsed")&&t.addClass("expanded")):t.addClass("node"),t.hasClass("node")){var n=l("<input type='checkbox' data-role='checkbox' data-style='"+s.checkStyle+"'>");n.data("node",t),t.prepend(n)}0<a&&l.each(s.structure,function(e){void 0!==t.data(e)&&l("<div>").addClass("node-data item-data-"+e).addClass(t.data(e)).html(t.data(e)).appendTo(t)})}),this.toggleSelectable(),this.view(s.view)},_createEvents:function(){var t=this,n=this.element,i=this.options;n.on(r.events.dblclick,".node",function(){var e=l(this);t._fireEvent("node-dblclick",{node:e})}),n.on(r.events.click,".node",function(){var e=l(this);n.find(".node").removeClass("current"),e.toggleClass("current"),!0===i.selectCurrent&&(n.find(".node").removeClass("current-select"),e.toggleClass("current-select")),t._fireEvent("node-click",{node:e})}),n.on(r.events.click,".node-toggle",function(){var e=l(this).closest("li");t.toggleNode(e)}),n.on(r.events.click,".node-group > .data > .caption",function(){var e=l(this).closest("li");n.find(".node-group").removeClass("current-group"),e.addClass("current-group"),c.exec(i.onGroupNodeClick,[e],n[0]),n.fire("groupnodeclick",{node:e})}),n.on(r.events.dblclick,".node-group > .data > .caption",function(){var e=l(this).closest("li");t.toggleNode(e),c.exec(i.onNodeDblClick,[e],n[0]),n.fire("nodedblclick",{node:e})})},view:function(e){var n=this.element,t=this.options;if(void 0===e)return t.view;t.view=e,l.each(r.listView,function(e,t){n.removeClass("view-"+t),n.find("ul").removeClass("view-"+t)}),n.addClass("view-"+t.view),n.find("ul").addClass("view-"+t.view)},toggleNode:function(e){var t,n=this.element,i=this.options;(e=l(e)).hasClass("node-group")&&(e.toggleClass("expanded"),t=!0!==e.hasClass("expanded")?"slideUp":"slideDown",c.exec(i.onCollapseNode,[e],n[0]),n.fire("collapsenode",{node:e}),e.children("ul")[t](i.duration))},toggleSelectable:function(){var e=this.element,t=!0===this.options.selectable?"addClass":"removeClass";e[t]("selectable"),e.find("ul")[t]("selectable")},add:function(e,t){var n,i,s=this.element,a=this.options;if(null===e)n=s;else{if(!(e=l(e)).hasClass("node-group"))return;0===(n=e.children("ul")).length&&(n=l("<ul>").addClass("listview").addClass("view-"+a.view).appendTo(e),this._createToggle().appendTo(e),e.addClass("expanded"))}(i=this._createNode(t)).addClass("node").appendTo(n);var o=l("<input type='checkbox'>");return o.data("node",i),i.prepend(o),r.makePlugin(o,"checkbox",{}),c.exec(a.onNodeInsert,[i,e,n],s[0]),s.fire("nodeinsert",{newNode:i,parentNode:e,list:n}),i},addGroup:function(e){var t,n=this.element,i=this.options;return delete e.icon,(t=this._createNode(e)).addClass("node-group").appendTo(n),t.append(this._createToggle()),t.addClass("expanded"),t.append(l("<ul>").addClass("listview").addClass("view-"+i.view)),c.exec(i.onNodeInsert,[t,null,n],n[0]),n.fire("nodeinsert",{newNode:t,parentNode:null,list:n}),t},insertBefore:function(e,t){var n,i,s,a=this.element,o=this.options;if((e=l(e)).length)return(n=this._createNode(t)).addClass("node").insertBefore(e),i=n.closest(".node"),s=n.closest("ul"),c.exec(o.onNodeInsert,[n,i,s],a[0]),a.fire("nodeinsert",{newNode:n,parentNode:i,list:s}),n},insertAfter:function(e,t){var n,i,s,a=this.element,o=this.options;if((e=l(e)).length)return(n=this._createNode(t)).addClass("node").insertAfter(e),i=n.closest(".node"),s=n.closest("ul"),c.exec(o.onNodeInsert,[n,i,s],a[0]),a.fire("nodeinsert",{newNode:n,parentNode:i,list:s}),n},del:function(e){var t=this.element,n=this.options;if((e=l(e)).length){var i=e.closest("ul"),s=i.closest("li");e.remove(),0!==i.children().length||i.is(t)||(i.remove(),s.removeClass("expanded"),s.children(".node-toggle").remove()),c.exec(n.onNodeDelete,[e],t[0]),t.fire("nodedelete",{node:e})}},clean:function(e){var t=this.element,n=this.options;(e=l(e)).length&&(e.children("ul").remove(),e.removeClass("expanded"),e.children(".node-toggle").remove(),c.exec(n.onNodeClean,[e],t[0]),t.fire("nodeclean",{node:e}))},getSelected:function(){var e=this.element,t=[];return l.each(e.find(":checked"),function(){var e=l(this);t.push(e.closest(".node")[0])}),t},clearSelected:function(){this.element.find(":checked").prop("checked",!1),this.element.trigger("change")},selectAll:function(e){this.element.find(".node > .checkbox input").prop("checked",!1!==e),this.element.trigger("change")},selectByAttribute:function(e,t,n){!1!==n&&(n=!0),this.element.find("li["+e+'="'+t+'"] > .checkbox input').prop("checked",n),this.element.trigger("change")},changeAttribute:function(e){var t,n=this,i=this.element,s=this.options;switch(e){case"data-view":t="view-"+i.attr("data-view"),n.view(t);break;case"data-selectable":s.selectable=!0===JSON.parse(i.attr("data-selectable")),n.toggleSelectable()}},destroy:function(){var e=this.element;return e.off(r.events.click,".node"),e.off(r.events.click,".node-toggle"),e.off(r.events.click,".node-group > .data > .caption"),e.off(r.events.dblclick,".node-group > .data > .caption"),e}})}(Metro,m4q),function(i,a){"use strict";var o=i.utils,n={masterDeferred:0,effect:"slide",effectFunc:"linear",duration:METRO_ANIMATION_DURATION,controlPrev:"<span class='default-icon-left-arrow'></span>",controlNext:"<span class='default-icon-right-arrow'></span>",controlTitle:"Master, page $1 of $2",backgroundImage:"",clsMaster:"",clsControls:"",clsControlPrev:"",clsControlNext:"",clsControlTitle:"",clsPages:"",clsPage:"",onBeforePage:i.noop_true,onBeforeNext:i.noop_true,onBeforePrev:i.noop_true,onNextPage:i.noop,onPrevPage:i.noop,onMasterCreate:i.noop};i.masterSetup=function(e){n=a.extend({},n,e)},window.metroMasterSetup,i.masterSetup(window.metroMasterSetup),i.Component("master",{init:function(e,t){return this._super(t,e,n,{pages:[],currentIndex:0,isAnimate:!1,id:o.elementId("master")}),this},_create:function(){var e=this.element,t=this.options;e.addClass("master").addClass(t.clsMaster),e.css({backgroundImage:"url("+t.backgroundImage+")"}),this._createControls(),this._createPages(),this._createEvents(),this._fireEvent("master-create",{element:e})},_createControls:function(){var e,t,n=this.element,i=this.options,s=n.find(".page");t=String(i.controlTitle).replace("$1","1"),t=String(t).replace("$2",s.length),a.each(["top","bottom"],function(){e=a("<div>").addClass("controls controls-"+this).addClass(i.clsControls).appendTo(n),a("<span>").addClass("prev").addClass(i.clsControlPrev).html(i.controlPrev).appendTo(e),a("<span>").addClass("next").addClass(i.clsControlNext).html(i.controlNext).appendTo(e),a("<span>").addClass("title").addClass(i.clsControlTitle).html(t).appendTo(e)}),this._enableControl("prev",!1)},_enableControl:function(e,t){var n=this.element.find(".controls ."+e);!0===t?n.removeClass("disabled"):n.addClass("disabled")},_setTitle:function(){var e=this.element.find(".controls .title"),t=this.options.controlTitle.replace("$1",this.currentIndex+1);t=t.replace("$2",String(this.pages.length)),e.html(t)},_createPages:function(){var t=this,n=this.element,i=this.options,e=n.find(".pages"),s=n.find(".page");0===e.length&&(e=a("<div>").addClass("pages").appendTo(n)),e.addClass(i.clsPages),a.each(s,function(){var e=a(this);void 0!==e.data("cover")?n.css({backgroundImage:"url("+e.data("cover")+")"}):n.css({backgroundImage:"url("+i.backgroundImage+")"}),e.css({left:"100%"}),e.addClass(i.clsPage).hide(0),t.pages.push(e)}),s.appendTo(e),void(this.currentIndex=0)!==this.pages[this.currentIndex]&&(void 0!==this.pages[this.currentIndex].data("cover")&&n.css({backgroundImage:"url("+this.pages[this.currentIndex].data("cover")+")"}),this.pages[this.currentIndex].css("left","0").show(0),setTimeout(function(){e.css({height:t.pages[0].outerHeight(!0)+2})},0))},_createEvents:function(){var e=this,t=this.element,n=this.options;t.on(i.events.click,".controls .prev",function(){!0!==e.isAnimate&&!0===o.exec(n.onBeforePrev,[e.currentIndex,e.pages[e.currentIndex],t])&&!0===o.exec(n.onBeforePage,["prev",e.currentIndex,e.pages[e.currentIndex],t])&&e.prev()}),t.on(i.events.click,".controls .next",function(){!0!==e.isAnimate&&!0===o.exec(n.onBeforeNext,[e.currentIndex,e.pages[e.currentIndex],t])&&!0===o.exec(n.onBeforePage,["next",e.currentIndex,e.pages[e.currentIndex],t])&&e.next()}),a(window).on(i.events.resize,function(){t.find(".pages").height(e.pages[e.currentIndex].outerHeight(!0)+2)},{ns:this.id})},_slideToPage:function(e){var t,n,i;void 0!==this.pages[e]&&this.currentIndex!==e&&(i=e>this.currentIndex?"next":"prev",t=this.pages[this.currentIndex],n=this.pages[e],this.currentIndex=e,this._effect(t,n,i))},_slideTo:function(e){var t,n,i=this.element,s=this.options,a="next"===e.toLowerCase();if(t=this.pages[this.currentIndex],a){if(this.currentIndex+1>=this.pages.length)return;this.currentIndex++}else{if(this.currentIndex-1<0)return;this.currentIndex--}n=this.pages[this.currentIndex],o.exec(a?s.onNextPage:s.onPrevPage,[t,n],i[0]),i.fire(a?"nextpage":"prevpage",{current:t,next:n,forward:a}),this._effect(t,n,e)},_effect:function(e,t,n){var i=this,s=this.element,a=this.options,o=s.width(),r=s.find(".pages");function l(){void 0!==t.data("cover")?s.css({backgroundImage:"url("+t.data("cover")+")"}):s.css({backgroundImage:"url("+a.backgroundImage+")"}),r.css("overflow","initial"),i.isAnimate=!1}switch(this._setTitle(),this.currentIndex===this.pages.length-1?this._enableControl("next",!1):this._enableControl("next",!0),0===this.currentIndex?this._enableControl("prev",!1):this._enableControl("prev",!0),this.isAnimate=!0,setTimeout(function(){r.animate({draw:{height:t.outerHeight(!0)+2}})},0),r.css("overflow","hidden"),a.effect){case"fade":e.fadeOut(a.duration),t.css({top:0,left:0,opacity:0}).fadeIn(a.duration,"linear",function(){l()});break;case"switch":e.hide(),t.css({top:0,left:0,opacity:0}).show(function(){l()});break;default:e.stop(!0).animate({draw:{left:"next"===n?-o:o},dur:a.duration,ease:a.effectFunc,onDone:function(){e.hide(0)}}),t.stop(!0).css({left:"next"===n?o:-o}).show(0).animate({draw:{left:0},dur:a.duration,ease:a.effectFunc,onDone:function(){l()}})}},toPage:function(e){this._slideToPage(e)},next:function(){this._slideTo("next")},prev:function(){this._slideTo("prev")},changeEffect:function(){this.options.effect=this.element.attr("data-effect")},changeEffectFunc:function(){this.options.effectFunc=this.element.attr("data-effect-func")},changeEffectDuration:function(){this.options.duration=this.element.attr("data-duration")},changeAttribute:function(e){switch(e){case"data-effect":this.changeEffect();break;case"data-effect-func":this.changeEffectFunc();break;case"data-duration":this.changeEffectDuration()}},destroy:function(){var e=this.element;return e.off(i.events.click,".controls .prev"),e.off(i.events.click,".controls .next"),a(window).off(i.events.resize,{ns:this.id}),e}})}(Metro,m4q),function(a,c){"use strict";var d=a.utils,n={navviewDeferred:0,compact:"md",expand:"lg",toggle:null,activeState:!1,onMenuItemClick:a.noop,onNavviewCreate:a.noop};a.navViewSetup=function(e){n=c.extend({},n,e)},window.metroNavViewSetup,a.navViewSetup(window.metroNavViewSetup),a.Component("nav-view",{init:function(e,t){return this._super(t,e,n,{pane:null,content:null,paneToggle:null,id:d.elementId("navview"),menuScrollDistance:0,menuScrollStep:0}),this},_create:function(){this._createStructure(),this._createEvents(),this._fireEvent("navview-create")},_calcMenuHeight:function(){var e,t,n=this.element,i=0;0!==(e=n.children(".navview-pane")).length&&0!==(t=e.children(".navview-menu-container")).length&&(c.each(t.prevAll(),function(){i+=c(this).outerHeight(!0)}),c.each(t.nextAll(),function(){i+=c(this).outerHeight(!0)}),t.css({height:"calc(100% - "+i+"px)"}),this.menuScrollStep=48,this.menuScrollDistance=d.nearest(t[0].scrollHeight-t.height(),48))},_recalc:function(){var e=this,t=this.element;setTimeout(function(){48===e.pane.width()?t.addClass("js-compact"):t.removeClass("js-compact"),e._calcMenuHeight()},200)},_createStructure:function(){var e,t,n,i,s=this.element,a=this.options;s.addClass("navview").addClass(!1!==a.compact?"navview-compact-"+a.compact:"").addClass(!1!==a.expand?"navview-expand-"+a.expand:""),e=s.children(".navview-pane"),t=s.children(".navview-content"),n=c(a.toggle),(i=e.children(".navview-menu")).length&&(i.prevAll().reverse().wrapAll(c("<div>").addClass("navview-container")),i.wrap(c("<div>").addClass("navview-menu-container"))),this.pane=0<e.length?e:null,this.content=0<t.length?t:null,this.paneToggle=0<n.length?n:null,this._recalc()},_createEvents:function(){var o=this,r=this.element,s=this.options,e=r.find(".navview-menu-container"),l=e.children(".navview-menu");e.on("mousewheel",function(e){var t=r.find(".navview-pane").width(),n=0<e.deltaY?-1:1,i=o.menuScrollStep,s=o.menuScrollDistance,a=parseInt(l.css("top"));if(48<t)return!1;-1==n&&Math.abs(a)<=s&&l.css("top",parseInt(l.css("top"))+i*n),1==n&&a<=-i&&l.css("top",parseInt(l.css("top"))+i*n)}),r.on(a.events.click,".pull-button, .holder",function(){o.pullClick(this)}),r.on(a.events.click,".navview-menu li",function(){!0===s.activeState&&(r.find(".navview-menu li").removeClass("active"),c(this).toggleClass("active"))}),r.on(a.events.click,".navview-menu li > a",function(){d.exec(s.onMenuItemClick,null,this),r.fire("menuitemclick",{item:this})}),null!==this.paneToggle&&this.paneToggle.on(a.events.click,function(){o.pane.toggleClass("open")}),c(window).on(a.events.resize,function(){var e,t,n,i=r.children(".navview-menu-container");o.pane.hasClass("open")||(r.removeClass("expanded"),o.pane.removeClass("open"),c(this).width()<=a.media_sizes[(""+s.compact).toUpperCase()]&&r.removeClass("compacted"),i.length&&(n=i.children(".navview-menu"),setTimeout(function(){e=n.height(),t=i.height(),o.menuScrollStep=n.children(":not(.item-separator), :not(.item-header)")[0].clientHeight,o.menuScrollDistance=t<e?d.nearest(e-t,o.menuScrollStep):0},0))),o._recalc()},{ns:this.id})},_togglePaneMode:function(){var e=this.element,t=this.pane.width()<280;!t&&!e.hasClass("expanded")||e.hasClass("compacted")?!e.hasClass("compacted")&&t||e.toggleClass("compacted"):e.toggleClass("expanded")},pullClick:function(e){var t,n=c(e);return n&&n.hasClass("holder")&&(t=n.parent().find("input"),setTimeout(function(){t.focus()},200)),this.pane.hasClass("open")?this.close():this._togglePaneMode(),this._recalc(),!0},open:function(){this.pane.addClass("open")},close:function(){this.pane.removeClass("open")},toggle:function(){var e=this.pane;e.hasClass("open")?e.removeClass("open"):e.addClass("open")},toggleMode:function(){this._togglePaneMode()},changeAttribute:function(e){},destroy:function(){var e=this.element;return e.off(a.events.click,".pull-button, .holder"),e.off(a.events.click,".navview-menu li"),e.off(a.events.click,".navview-menu li > a"),null!==this.paneToggle&&this.paneToggle.off(a.events.click),c(window).off(a.events.resize,{ns:this.id}),e}})}(Metro,m4q),function(l,c){"use strict";var d=l.utils,t={container:null,width:220,timeout:METRO_TIMEOUT,duration:METRO_ANIMATION_DURATION,distance:"max",animation:"linear",onClick:l.noop,onClose:l.noop,onShow:l.noop,onAppend:l.noop,onNotifyCreate:l.noop};l.notifySetup=function(e){t=c.extend({},t,e)},window.metroNotifySetup,l.notifySetup(window.metroNotifySetup);var u={container:null,options:{},notifies:[],setup:function(e){return this.options=c.extend({},t,e),this},reset:function(){var e={width:220,timeout:METRO_TIMEOUT,duration:METRO_ANIMATION_DURATION,distance:"max",animation:"linear"};this.options=c.extend({},t,e)},_createContainer:function(){var e=c("<div>").addClass("notify-container");return c("body").prepend(e),e},create:function(e,t,i){var s,n,a=this,o=this.options,r=d.elementId("notify");if(d.isNull(i)&&(i={}),!d.isValue(e))return!1;(s=c("<div>").addClass("notify").attr("id",r)).css({width:o.width}),t&&(n=c("<div>").addClass("notify-title").html(t),s.prepend(n)),c("<div>").addClass("notify-message").html(e).appendTo(s),void 0!==i&&(void 0!==i.cls&&s.addClass(i.cls),void 0!==i.width&&s.css({width:i.width})),s.on(l.events.click,function(){d.exec(d.isValue(i.onClick)?i.onClick:o.onClick,null,this),a.kill(c(this).closest(".notify"),d.isValue(i.onClose)?i.onClose:o.onClose)}),null===u.container&&(u.container=u._createContainer()),s.appendTo(u.container),s.hide(function(){d.exec(d.isValue(i.onAppend)?i.onAppend:o.onAppend,null,s[0]);var e=d.isValue(i.duration)?i.duration:o.duration,t=d.isValue(i.animation)?i.animation:o.animation,n=d.isValue(i.distance)?i.distance:o.distance;"max"!==n&&!isNaN(n)||(n=c(window).height()),s.show().animate({draw:{marginTop:[n,4],opacity:[0,1]},dur:e,ease:t,onDone:function(){d.exec(o.onNotifyCreate,null,this),void 0!==i&&!0===i.keepOpen||setTimeout(function(){a.kill(s,d.isValue(i.onClose)?i.onClose:o.onClose)},o.timeout),d.exec(d.isValue(i.onShow)?i.onShow:o.onShow,null,s[0])}})})},kill:function(e,t){var n=this,i=this.options;e.off(l.events.click),e.fadeOut(i.duration,"linear",function(){d.exec(d.isValue(t)?t:n.options.onClose,null,e[0]),e.remove()})},killAll:function(){var e=this,t=c(".notify");c.each(t,function(){e.kill(c(this))})}};l.notify=u.setup()}(Metro,m4q),function(e,c){"use strict";e.pagination=function(e){var t,n,i,s,a,o,r;if(t=c.extend({},{length:0,rows:0,current:0,target:"body",clsPagination:"",prevTitle:"Prev",nextTitle:"Next",distance:5},e),r=parseInt(t.distance),(i=c(t.target)).html(""),n=c("<ul>").addClass("pagination").addClass(t.clsPagination).appendTo(i),0!==t.length&&-1!==t.rows){t.pages=Math.ceil(t.length/t.rows);var l=function(e,t,n){var i,s;return i=c("<li>").addClass("page-item").addClass(t),(s=c("<a>").addClass("page-link").html(e)).data("page",n),s.appendTo(i),i};if(a=l(t.prevTitle,"service prev-page","prev"),n.append(a),n.append(l(1,1===t.current?"active":"",1)),0===r||t.pages<=7)for(s=2;s<t.pages;s++)n.append(l(s,s===t.current?"active":"",s));else if(t.current<r){for(s=2;s<=r;s++)n.append(l(s,s===t.current?"active":"",s));t.pages>r&&n.append(l("...","no-link",null))}else if(t.current<=t.pages&&t.current>t.pages-r+1)for(t.pages>r&&n.append(l("...","no-link",null)),s=t.pages-r+1;s<t.pages;s++)n.append(l(s,s===t.current?"active":"",s));else n.append(l("...","no-link",null)),n.append(l(t.current-1,"",t.current-1)),n.append(l(t.current,"active",t.current)),n.append(l(t.current+1,"",t.current+1)),n.append(l("...","no-link",null));return(1<t.pages||t.current<t.pages)&&n.append(l(t.pages,t.current===t.pages?"active":"",t.pages)),o=l(t.nextTitle,"service next-page","next"),n.append(o),1===t.current&&a.addClass("disabled"),t.current===t.pages&&o.addClass("disabled"),0===t.length&&(n.addClass("disabled"),n.children().addClass("disabled")),n}}}(Metro,m4q),function(l,c){"use strict";var d=l.utils,n={panelDeferred:0,id:null,titleCaption:"",titleIcon:"",collapsible:!1,collapsed:!1,collapseDuration:METRO_ANIMATION_DURATION,width:"auto",height:"auto",draggable:!1,customButtons:null,clsCustomButton:"",clsPanel:"",clsTitle:"",clsTitleCaption:"",clsTitleIcon:"",clsContent:"",clsCollapseToggle:"",onCollapse:l.noop,onExpand:l.noop,onDragStart:l.noop,onDragStop:l.noop,onDragMove:l.noop,onPanelCreate:l.noop};l.panelSetup=function(e){n=c.extend({},n,e)},window.metroPanelSetup,l.panelSetup(window.metroPanelSetup),l.Component("panel",{init:function(e,t){return this._super(t,e,n),this},_addCustomButtons:function(e){var t,n=this.element,i=this.options,s=n.closest(".panel").find(".panel-title"),a=[];if("string"==typeof e&&-1<e.indexOf("{"))a=JSON.parse(e);else if("string"==typeof e&&d.isObject(e))a=d.isObject(e);else{if(!("object"==typeof e&&0<d.objectLength(e)))return void console.warn("Unknown format for custom buttons",e);a=e}if(0!==s.length)return 0===(t=s.find(".custom-buttons")).length?t=c("<div>").addClass("custom-buttons").appendTo(s):(t.find(".btn-custom").off(l.events.click),t.html("")),c.each(a,function(){var e=c("<span>");e.addClass("button btn-custom").addClass(i.clsCustomButton).addClass(this.cls).attr("tabindex",-1).html(this.html),e.data("action",this.onclick),t.prepend(e)}),s.on(l.events.click,".btn-custom",function(e){if(!d.isRightMouse(e)){var t=c(this),n=t.data("action");d.exec(n,[t],this)}}),this;console.warn("No place for custom buttons")},_create:function(){var e,t,n=this.element,i=this.options,s=c("<div>").addClass("panel").addClass(i.clsPanel),a=i.id?i.id:d.elementId("panel"),o=n[0].className;if(s.attr("id",a).addClass(o),s.insertBefore(n),n.appendTo(s),n[0].className="",n.addClass("panel-content").addClass(i.clsContent).appendTo(s),""!==i.titleCaption||""!==i.titleIcon||!0===i.collapsible){if(e=c("<div>").addClass("panel-title").addClass(i.clsTitle),""!==i.titleCaption&&c("<span>").addClass("caption").addClass(i.clsTitleCaption).html(i.titleCaption).appendTo(e),""!==i.titleIcon&&c(i.titleIcon).addClass("icon").addClass(i.clsTitleIcon).appendTo(e),!0===i.collapsible){var r=c("<span>").addClass("dropdown-toggle marker-center active-toggle").addClass(i.clsCollapseToggle).appendTo(e);l.makePlugin(n,"collapse",{toggleElement:r,duration:i.collapseDuration,onCollapse:i.onCollapse,onExpand:i.onExpand}),!0===i.collapsed&&this.collapse()}e.appendTo(s)}e&&d.isValue(i.customButtons)&&this._addCustomButtons(i.customButtons),!0===i.draggable&&(t=e?e.find(".caption, .icon"):s,l.makePlugin(s,"draggable",{dragContext:s[0],dragElement:t,onDragStart:i.onDragStart,onDragStop:i.onDragStop,onDragMove:i.onDragMove}));"auto"!==i.width&&0<=parseInt(i.width)&&s.outerWidth(parseInt(i.width)),"auto"!==i.height&&0<=parseInt(i.height)&&(s.outerHeight(parseInt(i.height)),n.css({overflow:"auto"})),this.panel=s,this._fireEvent("panel-create",{element:n,panel:s})},customButtons:function(e){return this._addCustomButtons(e)},collapse:function(){var e=this.element;!1!==d.isMetroObject(e,"collapse")&&l.getPlugin(e,"collapse").collapse()},open:function(){this.expand()},close:function(){this.collapse()},expand:function(){var e=this.element;!1!==d.isMetroObject(e,"collapse")&&l.getPlugin(e,"collapse").expand()},changeAttribute:function(e){},destroy:function(){var e=this.element,t=this.options;return!0===t.collapsible&&l.getPlugin(e,"collapse").destroy(),!0===t.draggable&&l.getPlugin(e,"draggable").destroy(),e}})}(Metro,m4q),function(l,c){"use strict";var d=l.utils,n={popoverDeferred:0,popoverText:"",popoverHide:3e3,popoverTimeout:10,popoverOffset:10,popoverTrigger:l.popoverEvents.HOVER,popoverPosition:l.position.TOP,hideOnLeave:!1,closeButton:!0,clsPopover:"",clsPopoverContent:"",onPopoverShow:l.noop,onPopoverHide:l.noop,onPopoverCreate:l.noop};l.popoverSetup=function(e){n=c.extend({},n,e)},window.metroPopoverSetup,l.popoverSetup(window.metroPopoverSetup),l.Component("popover",{init:function(e,t){return this._super(t,e,n,{popover:null,popovered:!1,size:{width:0,height:0},id:d.elementId("popover")}),this},_create:function(){this._createEvents(),this._fireEvent("popover-create",{element:this.element})},_createEvents:function(){var e,t=this,n=this.element,i=this.options;switch(i.popoverTrigger){case l.popoverEvents.CLICK:e=l.events.click;break;case l.popoverEvents.FOCUS:e=l.events.focus;break;default:e=l.events.enter}n.on(e,function(){null===t.popover&&!0!==t.popovered&&setTimeout(function(){t.createPopover(),d.exec(i.onPopoverShow,[t.popover],n[0]),n.fire("popovershow",{popover:t.popover}),0<i.popoverHide&&setTimeout(function(){t.removePopover()},i.popoverHide)},i.popoverTimeout)}),!0===i.hideOnLeave&&n.on(l.events.leave,function(){t.removePopover()}),c(window).on(l.events.scroll,function(){null!==t.popover&&t.setPosition()},{ns:this.id})},setPosition:function(){var e=this.popover,t=this.size,n=this.options,i=this.element;n.popoverPosition===l.position.BOTTOM?(e.addClass("bottom"),e.css({top:i.offset().top-c(window).scrollTop()+i.outerHeight()+n.popoverOffset,left:i.offset().left+i.outerWidth()/2-t.width/2-c(window).scrollLeft()})):n.popoverPosition===l.position.RIGHT?(e.addClass("right"),e.css({top:i.offset().top+i.outerHeight()/2-t.height/2-c(window).scrollTop(),left:i.offset().left+i.outerWidth()-c(window).scrollLeft()+n.popoverOffset})):n.popoverPosition===l.position.LEFT?(e.addClass("left"),e.css({top:i.offset().top+i.outerHeight()/2-t.height/2-c(window).scrollTop(),left:i.offset().left-t.width-c(window).scrollLeft()-n.popoverOffset})):(e.addClass("top"),e.css({top:i.offset().top-c(window).scrollTop()-t.height-n.popoverOffset,left:i.offset().left+i.outerWidth()/2-t.width/2-c(window).scrollLeft()}))},createPopover:function(){var e,t,n=this,i=this.elem,s=this.element,a=this.options,o=d.elementId("popover");if(!this.popovered){switch((e=c("<div>").addClass("popover neb").addClass(a.clsPopover)).attr("id",o),c("<div>").addClass("popover-content").addClass(a.clsPopoverContent).html(a.popoverText).appendTo(e),0===a.popoverHide&&!0===a.closeButton&&c("<button>").addClass("button square small popover-close-button bg-white").html("&times;").appendTo(e).on(l.events.click,function(){n.removePopover()}),a.popoverPosition){case l.position.TOP:t="neb-s";break;case l.position.BOTTOM:t="neb-n";break;case l.position.RIGHT:t="neb-w";break;case l.position.LEFT:t="neb-e"}if(e.addClass(t),!0!==a.closeButton&&e.on(l.events.click,function(){n.removePopover()}),this.popover=e,this.size=d.hiddenElementSize(e),"TD"===i.tagName||"TH"===i.tagName){var r=c("<div/>").css("display","inline-block").html(s.html());s.html(r),s=r}this.setPosition(),e.appendTo(c("body")),this.popovered=!0,d.exec(a.onPopoverCreate,[s,e],s[0]),s.fire("popovercreate",{popover:e})}},removePopover:function(){var e=this,t=this.element,n=this.options.onPopoverHide===l.noop?0:300,i=this.popover;this.popovered&&(d.exec(this.options.onPopoverHide,[i],this.elem),t.fire("popoverhide",{popover:i}),setTimeout(function(){i.hide(0,function(){i.remove(),e.popover=null,e.popovered=!1})},n))},show:function(){var e=this,t=this.element,n=this.options;!0!==this.popovered&&setTimeout(function(){e.createPopover(),d.exec(n.onPopoverShow,[e.popover],t[0]),t.fire("popovershow",{popover:e.popover}),0<n.popoverHide&&setTimeout(function(){e.removePopover()},n.popoverHide)},n.popoverTimeout)},hide:function(){this.removePopover()},changeAttribute:function(e){var t=this,n=this.element,i=this.options;switch(e){case"data-popover-text":i.popoverText=n.attr("data-popover-text"),t.popover&&(t.popover.find(".popover-content").html(i.popoverText),t.setPosition());break;case"data-popover-position":i.popoverPosition=n.attr("data-popover-position"),t.setPosition()}},destroy:function(){var e,t=this.element,n=this.options;switch(n.popoverTrigger){case l.popoverEvents.CLICK:e=l.events.click;break;case l.popoverEvents.FOCUS:e=l.events.focus;break;default:e=l.events.enter}return t.off(e),!0===n.hideOnLeave&&t.off(l.events.leave),c(window).off(l.events.scroll,{ns:this.id}),t}})}(Metro,m4q),function(e,s){"use strict";var l=e.utils,n={progressDeferred:0,showValue:!1,valuePosition:"free",showLabel:!1,labelPosition:"before",labelTemplate:"",value:0,buffer:0,type:"bar",small:!1,clsBack:"",clsBar:"",clsBuffer:"",clsValue:"",clsLabel:"",onValueChange:e.noop,onBufferChange:e.noop,onComplete:e.noop,onBuffered:e.noop,onProgressCreate:e.noop};e.progressSetup=function(e){n=s.extend({},n,e)},window.metroProgressSetup,e.progressSetup(window.metroProgressSetup),e.Component("progress",{init:function(e,t){return this._super(t,e,n,{value:0,buffer:0}),this},_create:function(){var e,t=this.element,n=this.options;switch("string"==typeof n.type&&(n.type=n.type.toLowerCase()),t.html("").addClass("progress"),n.type){case"buffer":s("<div>").addClass("bar").appendTo(t),s("<div>").addClass("buffer").appendTo(t);break;case"load":t.addClass("with-load"),s("<div>").addClass("bar").appendTo(t),s("<div>").addClass("buffer").appendTo(t),s("<div>").addClass("load").appendTo(t);break;case"line":t.addClass("line");break;default:s("<div>").addClass("bar").appendTo(t)}if("line"!==n.type&&(e=s("<span>").addClass("value").addClass(n.clsValue).appendTo(t),"center"===n.valuePosition&&e.addClass("centered"),!1===n.showValue&&e.hide()),!0===n.small&&t.addClass("small"),t.addClass(n.clsBack),t.find(".bar").addClass(n.clsBar),t.find(".buffer").addClass(n.clsBuffer),!0===n.showLabel){var i=s("<span>").addClass("progress-label").addClass(n.clsLabel).html(""===n.labelTemplate?n.value+"%":n.labelTemplate.replace("%VAL%",n.value));"before"===n.labelPosition?i.insertBefore(t):i.insertAfter(t)}this.val(n.value),this.buff(n.buffer),this._fireEvent("progress-create",{element:t})},val:function(e){var t=this.element,n=this.options,i=t.find(".value");if(void 0===e)return this.value;var s=t.find(".bar");if(0===s.length)return!1;this.value=parseInt(e,10),s.css("width",this.value+"%"),i.html(this.value+"%");var a=t.width()-s.width(),o=i.width()>a?{left:"auto",right:a+"px"}:{left:e+"%"};if("free"===n.valuePosition&&i.css(o),!0===n.showLabel){var r=t["before"===n.labelPosition?"prev":"next"](".progress-label");r.length&&r.html(""===n.labelTemplate?n.value+"%":n.labelTemplate.replace("%VAL%",n.value))}l.exec(n.onValueChange,[this.value],t[0]),t.fire("valuechange",{vsl:this.value}),100===this.value&&(l.exec(n.onComplete,[this.value],t[0]),t.fire("complete",{val:this.value}))},buff:function(e){var t=this.element,n=this.options;if(void 0===e)return this.buffer;var i=t.find(".buffer");if(0===i.length)return!1;this.buffer=parseInt(e,10),i.css("width",this.buffer+"%"),l.exec(n.onBufferChange,[this.buffer],t[0]),t.fire("bufferchange",{val:this.buffer}),100===this.buffer&&(l.exec(n.onBuffered,[this.buffer],t[0]),t.fire("buffered",{val:this.buffer}))},changeValue:function(){this.val(this.element.attr("data-value"))},changeBuffer:function(){this.buff(this.element.attr("data-buffer"))},changeAttribute:function(e){switch(e){case"data-value":this.changeValue();break;case"data-buffer":this.changeBuffer()}},destroy:function(){return this.element}})}(Metro,m4q),function(e,a){"use strict";var o=e.utils,n={radioDeferred:0,transition:!0,style:1,caption:"",captionPosition:"right",clsRadio:"",clsCheck:"",clsCaption:"",onRadioCreate:e.noop};e.radioSetup=function(e){n=a.extend({},n,e)},window.metroRadioSetup,e.radioSetup(window.metroRadioSetup),e.Component("radio",{init:function(e,t){return this._super(t,e,n,{origin:{className:""}}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("radio-create",{element:e})},_createStructure:function(){var e=this.element,t=this.options,n=a("<label>").addClass("radio "+e[0].className).addClass(2===t.style?"style2":""),i=a("<span>").addClass("check"),s=a("<span>").addClass("caption").html(t.caption);e.attr("type","radio"),n.insertBefore(e),e.appendTo(n),i.appendTo(n),s.appendTo(n),!0===t.transition&&n.addClass("transition-on"),"left"===t.captionPosition&&n.addClass("caption-left"),this.origin.className=e[0].className,e[0].className="",n.addClass(t.clsRadio),s.addClass(t.clsCaption),i.addClass(t.clsCheck),e.is(":disabled")?this.disable():this.enable()},_createEvents:function(){var e=this.element,t=e.siblings(".check");e.on("focus",function(){t.addClass("focused")}),e.on("blur",function(){t.removeClass("focused")})},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},changeAttribute:function(e){var t,n=this.element,i=this.options,s=n.parent();switch(e){case"disabled":this.toggleState();break;case"data-style":t=parseInt(n.attr("data-style")),o.isInt(t)&&(i.style=t,s.removeClass("style1 style2").addClass("style"+t))}},destroy:function(){return this.element}})}(Metro,m4q),function(u,h){"use strict";var p=u.utils,i=u.colors,n={ratingDeferred:0,static:!1,title:null,value:0,values:null,message:"",stars:5,starColor:null,staredColor:null,roundFunc:"round",half:!0,clsRating:"",clsTitle:"",clsStars:"",clsResult:"",onStarClick:u.noop,onRatingCreate:u.noop};u.ratingSetup=function(e){n=h.extend({},n,e)},window.metroRatingSetup,u.ratingSetup(window.metroRatingSetup),u.Component("rating",{init:function(e,t){return this._super(t,e,n,{value:0,originValue:0,values:[],rate:0,rating:null}),this},_create:function(){var e,t=this.element,n=this.options;if(isNaN(n.value)?n.value=0:n.value=parseFloat(n.value).toFixed(1),null!==n.values)Array.isArray(n.values)?this.values=n.values:"string"==typeof n.values&&(this.values=n.values.toArray());else for(e=1;e<=n.stars;e++)this.values.push(e);this.originValue=n.value,this.value=0<n.value?Math[n.roundFunc](n.value):0,null!==n.starColor&&(p.isColor(n.starColor)||(n.starColor=i.color(n.starColor))),null!==n.staredColor&&(p.isColor(n.staredColor)||(n.staredColor=i.color(n.staredColor))),this._createRating(),this._createEvents(),this._fireEvent("rating-create",{element:t})},_createRating:function(){var e,t,n,i=this.element,s=this.options,a=p.elementId("rating"),o=h("<div>").addClass("rating "+String(i[0].className).replace("d-block","d-flex")).addClass(s.clsRating),r=u.sheet,l=s.static?Math.floor(this.originValue):this.value;for(i.val(this.value),o.attr("id",a),o.insertBefore(i),i.appendTo(o),t=h("<ul>").addClass("stars").addClass(s.clsStars).appendTo(o),e=1;e<=s.stars;e++)n=h("<li>").data("value",this.values[e-1]).appendTo(t),e<=l&&n.addClass("on");if(h("<span>").addClass("result").addClass(s.clsResult).appendTo(o).html(s.message),null!==s.starColor&&p.addCssRule(r,"#"+a+" .stars:hover li","color: "+s.starColor+";"),null!==s.staredColor&&(p.addCssRule(r,"#"+a+" .stars li.on","color: "+s.staredColor+";"),p.addCssRule(r,"#"+a+" .stars li.half::after","color: "+s.staredColor+";")),null!==s.title){var c=h("<span>").addClass("title").addClass(s.clsTitle).html(s.title);o.prepend(c)}if(!0===s.static&&(o.addClass("static"),!0===s.half)){var d=Math.round(this.originValue%1*10);0<d&&d<=9&&o.find(".stars li.on").last().next("li").addClass("half half-"+10*d)}if(!(i[0].className="")===s.copyInlineStyles)for(e=0;e<i[0].style.length;e++)o.css(i[0].style[e],i.css(i[0].style[e]));i.is(":disabled")?this.disable():this.enable(),this.rating=o},_createEvents:function(){var n=this.element,i=this.options;this.rating.on(u.events.click,".stars li",function(){if(!0!==i.static){var e=h(this),t=e.data("value");e.addClass("scale"),setTimeout(function(){e.removeClass("scale")},300),n.val(t).trigger("change"),e.addClass("on"),e.prevAll().addClass("on"),e.nextAll().removeClass("on"),p.exec(i.onStarClick,[t,e[0]],n[0]),n.fire("starclick",{value:t,star:e[0]})}})},val:function(e){var t=this,n=this.element,i=this.options,s=this.rating;if(void 0===e)return this.value;this.value=0<e?Math[i.roundFunc](e):0,n.val(this.value).trigger("change");var a=s.find(".stars li").removeClass("on");return h.each(a,function(){var e=h(this);e.data("value")<=t.value&&e.addClass("on")}),this},msg:function(e){var t=this.rating;if(void 0!==e)return t.find(".result").html(e),this},static:function(e){var t=this.options,n=this.rating;!0===(t.static=e)?n.addClass("static"):n.removeClass("static")},changeAttributeValue:function(e){var t=this.element,n="value"===e?t.val():t.attr("data-value");this.val(n)},changeAttributeMessage:function(){var e=this.element.attr("data-message");this.msg(e)},changeAttributeStatic:function(){var e=this.element,t=!0===JSON.parse(e.attr("data-static"));this.static(t)},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},changeAttribute:function(e){switch(e){case"value":case"data-value":this.changeAttributeValue(e);break;case"disabled":this.toggleState();break;case"data-message":this.changeAttributeMessage();break;case"data-static":this.changeAttributeStatic()}},destroy:function(){var e=this.element;return this.rating.off(u.events.click,".stars li"),e}})}(Metro,m4q),function(l,c){"use strict";var d=l.utils,n={resizableDeferred:0,canResize:!0,resizeElement:".resize-element",minWidth:0,minHeight:0,maxWidth:0,maxHeight:0,preserveRatio:!1,onResizeStart:l.noop,onResizeStop:l.noop,onResize:l.noop,onResizableCreate:l.noop};l.resizableSetup=function(e){n=c.extend({},n,e)},window.metroResizableSetup,l.resizableSetup(window.metroResizableSetup),l.Component("resizable",{init:function(e,t){return this._super(t,e,n,{resizer:null,id:d.elementId("resizable")}),this},_create:function(){this._createStructure(),this._createEvents(),this._fireEvent("resizable-create")},_createStructure:function(){var e=this.element,t=this.options;e.data("canResize",!0),e.addClass("resizable-element"),d.isValue(t.resizeElement)&&0<e.find(t.resizeElement).length?this.resizer=e.find(t.resizeElement):this.resizer=c("<span>").addClass("resize-element").appendTo(e),e.data("canResize",t.canResize)},_createEvents:function(){var n=this,o=this.element,r=this.options;this.resizer.on(l.events.start,function(e){if(!1!==o.data("canResize")){var i=d.pageXY(e),s=parseInt(o.outerWidth()),a=parseInt(o.outerHeight()),t={width:s,height:a};o.addClass("stop-pointer"),d.exec(r.onResizeStart,[t],o[0]),o.fire("resizestart",{size:t}),c(document).on(l.events.move,function(e){var t=d.pageXY(e),n={width:s+t.x-i.x,height:a+t.y-i.y};return 0<r.maxWidth&&n.width>r.maxWidth||(0<r.minWidth&&n.width<r.minWidth||(0<r.maxHeight&&n.height>r.maxHeight||(0<r.minHeight&&n.height<r.minHeight||(o.css(n),d.exec(r.onResize,[n],o[0]),void o.fire("resize",{size:n})))))},{ns:n.id}),c(document).on(l.events.stop,function(){o.removeClass("stop-pointer"),c(document).off(l.events.move,{ns:n.id}),c(document).off(l.events.stop,{ns:n.id});var e={width:parseInt(o.outerWidth()),height:parseInt(o.outerHeight())};d.exec(r.onResizeStop,[e],o[0]),o.fire("resizestop",{size:e})},{ns:n.id}),e.preventDefault(),e.stopPropagation()}})},off:function(){this.element.data("canResize",!1)},on:function(){this.element.data("canResize",!0)},changeAttribute:function(e){var t=this.element,n=this.options;switch(e){case"data-can-resize":n.canResize=!0===JSON.parse(t.attr("data-can-resize"))}},destroy:function(){return this.resizer.off(l.events.start),this.element}})}(Metro,m4q),function(e,t){"use strict";var d=e.utils,n={resizerDeferred:0,onMediaPoint:e.noop,onMediaPointEnter:e.noop,onMediaPointLeave:e.noop,onWindowResize:e.noop,onElementResize:e.noop,onResizerCreate:e.noop};e.resizerSetup=function(e){n=t.extend({},n,e)},window.metroResizerSetup,e.resizerSetup(window.metroResizerSetup),e.Component("resizer",{init:function(e,t){return this._super(t,e,n,{size:{width:0,height:0},media:window.METRO_MEDIA,id:d.elementId("resizer")}),this},_create:function(){var e=this.element;this.size={width:e.width(),height:e.height()},this._createStructure(),this._createEvents(),this._fireEvent("resizer-create",{element:e})},_createStructure:function(){},_createEvents:function(){var o=this,r=this.element,l=this.options,c=t.window();c.on("resize",function(){var e,t=c.width(),n=c.height(),i=r.width(),s=r.height(),a=o.size;d.exec(l.onWindowResize,[t,n,window.METRO_MEDIA],r[0]),r.fire("windowresize",{width:t,height:n,media:window.METRO_MEDIA}),o.size.width===i&&o.size.height===s||(o.size={width:i,height:s},d.exec(l.onElementResize,[i,s,a,window.METRO_MEDIA],r[0]),r.fire("windowresize",{width:i,height:s,oldSize:a,media:window.METRO_MEDIA})),o.media.length!==window.METRO_MEDIA.length&&(o.media.length>window.METRO_MEDIA.length?(e=o.media.filter(function(e){return!window.METRO_MEDIA.contains(e)}),d.exec(l.onMediaPointLeave,[e,window.METRO_MEDIA],r[0]),r.fire("mediapointleave",{point:e,media:window.METRO_MEDIA})):(e=window.METRO_MEDIA.filter(function(e){return!o.media.contains(e)}),d.exec(l.onMediaPointEnter,[e,window.METRO_MEDIA],r[0]),r.fire("mediapointenter",{point:e,media:window.METRO_MEDIA})),o.media=window.METRO_MEDIA,d.exec(l.onMediaPoint,[e,window.METRO_MEDIA],r[0]),r.fire("mediapoint",{point:e,media:window.METRO_MEDIA}))},{ns:this.id})},changeAttribute:function(){},destroy:function(){t(window).off("resize",{ns:this.id})}})}(Metro,m4q),function(o,l){"use strict";var c=o.utils,n={ribbonmenuDeferred:0,onStatic:o.noop,onBeforeTab:o.noop_true,onTab:o.noop,onRibbonMenuCreate:o.noop};o.ribbonMenuSetup=function(e){n=l.extend({},n,e)},window.metroRibbonMenuSetup,o.ribbonMenuSetup(window.metroRibbonMenuSetup),o.Component("ribbon-menu",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("ribbon-menu-create",{element:e})},_createStructure:function(){var e=this.element;e.addClass("ribbon-menu");var t=e.find(".tabs-holder li:not(.static)"),n=e.find(".tabs-holder li.active");0<n.length?this.open(l(n[0])):0<t.length&&this.open(l(t[0]));var i=e.find(".ribbon-toggle-group");l.each(i,function(){var e=l(this);e.buttongroup({clsActive:"active"});var t=0,n=e.find(".ribbon-icon-button");l.each(n,function(){var e=l(this).outerWidth(!0);t<e&&(t=e)}),e.css("width",t*Math.ceil(n.length/3)+4)})},_createEvents:function(){var i=this,s=this.element,a=this.options;s.on(o.events.click,".tabs-holder li a",function(e){var t=l(this),n=l(this).parent("li");n.hasClass("static")?a.onStatic===o.noop&&void 0!==t.attr("href")?document.location.href=t.attr("href"):(c.exec(a.onStatic,[n[0]],s[0]),s.fire("static",{tab:n[0]})):!0===c.exec(a.onBeforeTab,[n[0]],s[0])&&i.open(n[0]),e.preventDefault()})},open:function(e){var t=this.element,n=this.options,i=l(e),s=t.find(".tabs-holder li"),a=t.find(".content-holder .section"),o=i.children("a").attr("href"),r="#"!==o?t.find(o):null;s.removeClass("active"),i.addClass("active"),a.removeClass("active"),r&&r.addClass("active"),c.exec(n.onTab,[i[0]],t[0]),t.fire("tab",{tab:i[0]})},changeAttribute:function(){},destroy:function(){var e=this.element;return e.off(o.events.click,".tabs-holder li a"),e}})}(Metro,m4q),function(i,d){"use strict";var u=i.utils,n={rippleDeferred:0,rippleColor:"#fff",rippleAlpha:.4,rippleTarget:"default",onRippleCreate:i.noop};i.rippleSetup=function(e){n=d.extend({},n,e)},window.metroRippleSetup,i.rippleSetup(window.metroRippleSetup);function s(e,t,n,i){var s,a,o=d(e),r=u.rect(o[0]);if(0!==o.length){u.isValue(t)||(t="#fff"),u.isValue(n)||(n=.4),"static"===o.css("position")&&o.css("position","relative"),o.css({overflow:"hidden"}),d(".ripple").remove();var l=Math.max(o.outerWidth(),o.outerHeight()),c=d("<span class='ripple'></span>").css({width:l,height:l});o.prepend(c),a=i?(s=i.pageX-o.offset().left-c.width()/2,i.pageY-o.offset().top-c.height()/2):(s=r.width/2-c.width()/2,r.height/2-c.height()/2),c.css({background:u.hex2rgba(t,n),width:l,height:l,top:a+"px",left:s+"px"}).addClass("rippleEffect"),setTimeout(function(){c.remove()},400)}}i.Component("ripple",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e=this.element,t=this.options,n="default"===t.rippleTarget?null:t.rippleTarget;e.on(i.events.click,n,function(e){s(this,t.rippleColor,t.rippleAlpha,e)}),this._fireEvent("riopple-create",{element:e})},changeAttribute:function(e){var t,n,i=this.element,s=this.options;switch(e){case"data-ripple-color":n=i.attr("data-ripple-color"),u.isColor(n)&&(s.rippleColor=n);break;case"data-ripple-alpha":t=+i.attr("data-ripple-alpha"),isNaN(t)||(s.rippleColor=t)}},destroy:function(){var e=this.element,t=this.options,n="default"===t.rippleTarget?null:t.rippleTarget;e.off(i.events.click,n)}}),i.ripple=s}(Metro,m4q),function(v,g){"use strict";var w=v.utils,n={size:"normal",selectDeferred:0,clearButton:!1,clearButtonIcon:"<span class='default-icon-cross'></span>",usePlaceholder:!1,placeholder:"",addEmptyValue:!1,emptyValue:"",duration:100,prepend:"",append:"",filterPlaceholder:"",filter:!0,copyInlineStyles:!1,dropHeight:200,clsSelect:"",clsSelectInput:"",clsPrepend:"",clsAppend:"",clsOption:"",clsOptionActive:"",clsOptionGroup:"",clsDropList:"",clsDropContainer:"",clsSelectedItem:"",clsSelectedItemRemover:"",onChange:v.noop,onUp:v.noop,onDrop:v.noop,onItemSelect:v.noop,onItemDeselect:v.noop,onSelectCreate:v.noop};v.selectSetup=function(e){n=g.extend({},n,e)},window.metroSelectSetup,v.selectSetup(window.metroSelectSetup),v.Component("select",{init:function(e,t){return this._super(t,e,n,{list:null,placeholder:null}),this},_create:function(){var e=this.element;this._createSelect(),this._createEvents(),this._fireEvent("select-create",{element:e})},_setPlaceholder:function(){var e=this.element,t=this.options,n=e.siblings(".select-input");!0!==t.usePlaceholder||w.isValue(e.val())&&e.val()!=t.emptyValue||n.html(this.placeholder)},_addTag:function(e,t){var n,i,s=this.element,a=this.options,o=s.closest(".select");return n=g("<div>").addClass("tag").addClass(a.clsSelectedItem).html("<span class='title'>"+e+"</span>").data("option",t),g("<span>").addClass("remover").addClass(a.clsSelectedItemRemover).html("&times;").appendTo(n),o.hasClass("input-large")?i="large":o.hasClass("input-small")&&(i="small"),n.addClass(i),n},_addOption:function(e,t,n,i){var s,a,o=g(e),r=this.element,l=this.options,c=w.isValue(o.attr("data-template"))?o.attr("data-template").replace("$1",e.text):e.text;s=g("<li>").addClass(l.clsOption).data("option",e).attr("data-text",e.text).attr("data-value",e.value?e.value:""),a=g("<a>").html(c),s.addClass(e.className),o.is(":disabled")&&s.addClass("disabled"),o.is(":selected")&&(i?(s.addClass("d-none"),n.append(this._addTag(c,s))):(r.val(e.value),n.html(c),r.fire("change",{val:e.value}),s.addClass("active"))),s.append(a).appendTo(t)},_addOptionGroup:function(e,t,n,i){var s=this,a=g(e);g("<li>").html(e.label).addClass("group-title").appendTo(t),g.each(a.children(),function(){s._addOption(this,t,n,i)})},_createOptions:function(){var e=this,t=this.element,n=this.options,i=t.parent().find("ul").empty(),s=0<t.find("option[selected]").length,a=t[0].multiple,o=t.siblings(".select-input");t.siblings(".select-input").empty(),!0===n.addEmptyValue&&t.prepend(g("<option "+(s?"":"selected")+" value='"+n.emptyValue+"' class='d-none'></option>")),g.each(t.children(),function(){"OPTION"===this.tagName?e._addOption(this,i,o,a):"OPTGROUP"===this.tagName&&e._addOptionGroup(this,i,o,a)})},_createSelect:function(){var e,n,t,i,s,a,o=this.element,r=this.options,l=g("<label>").addClass("select "+o[0].className).addClass(r.clsSelect),c=o[0].multiple,d=w.elementId("select"),u=g("<div>").addClass("button-group"),h=w.elementId("select-focus-trigger"),p=g("<input type='checkbox'>").addClass("select-focus-trigger").attr("id",h);(this.placeholder=g("<span>").addClass("placeholder").html(r.placeholder),l.attr("id",d).attr("for",h),l.addClass("input-"+r.size),(a=g("<span>").addClass("dropdown-toggle")).appendTo(l),c&&l.addClass("multiple"),l.insertBefore(o),o.appendTo(l),u.appendTo(l),p.appendTo(l),e=g("<div>").addClass("select-input").addClass(r.clsSelectInput).attr("name","__"+d+"__"),n=g("<div>").addClass("drop-container").addClass(r.clsDropContainer),t=g("<div>").appendTo(n),i=g("<ul>").addClass("option-list").addClass(r.clsDropList).css({"max-height":r.dropHeight}),s=g("<input type='text' data-role='input'>").attr("placeholder",r.filterPlaceholder).appendTo(t),l.append(e),l.append(n),n.append(t),!0!==r.filter&&t.hide(),n.append(i),this._createOptions(),this._setPlaceholder(),v.makePlugin(n,"dropdown",{dropFilter:".select",duration:r.duration,toggleElement:[l],onDrop:function(){var e,t;a.addClass("active-toggle"),e=g(".select .drop-container"),g.each(e,function(){var e=g(this);if(!e.is(n)){var t=e.data("dropdown");t&&t.close&&t.close()}}),s.val("").trigger(v.events.keyup).focus(),void 0!==(t=0<i.find("li.active").length?g(i.find("li.active")[0]):void 0)&&(i[0].scrollTop=t.position().top-(i.height()-t.height())/2),w.exec(r.onDrop,[i[0]],o[0]),o.fire("drop",{list:i[0]})},onUp:function(){a.removeClass("active-toggle"),w.exec(r.onUp,[i[0]],o[0]),o.fire("up",{list:i[0]})}}),this.list=i,!0!==r.clearButton||o[0].readOnly)?u.addClass("d-none"):g("<button>").addClass("button input-clear-button").addClass(r.clsClearButton).attr("tabindex",-1).attr("type","button").html(r.clearButtonIcon).appendTo(u);""===r.prepend||c||g("<div>").html(r.prepend).addClass("prepend").addClass(r.clsPrepend).appendTo(l);""===r.append||c||g("<div>").html(r.append).addClass("append").addClass(r.clsAppend).appendTo(l);if(!0===r.copyInlineStyles)for(var f=0,m=o[0].style.length;f<m;f++)l.css(o[0].style[f],o.css(o[0].style[f]));"rtl"===o.attr("dir")&&l.addClass("rtl").attr("dir","rtl"),o.is(":disabled")?this.disable():this.enable()},_createEvents:function(){var r=this,l=this.element,c=this.options,e=l.closest(".select"),d=e.find(".drop-container"),u=l.siblings(".select-input"),t=d.find("input"),h=d.find("ul"),n=e.find(".input-clear-button"),i=e.find(".select-focus-trigger");i.on("focus",function(){e.addClass("focused")}),i.on("blur",function(){e.removeClass("focused")}),n.on(v.events.click,function(e){l.val(c.emptyValue),l[0].multiple&&h.find("li").removeClass("d-none"),r._setPlaceholder(),e.preventDefault(),e.stopPropagation()}),l.on(v.events.change,function(){r._setPlaceholder()}),e.on(v.events.click,function(){g(".focused").removeClass("focused"),e.addClass("focused")}),u.on(v.events.click,function(){g(".focused").removeClass("focused"),e.addClass("focused")}),h.on(v.events.click,"li",function(e){if(g(this).hasClass("group-title"))return e.preventDefault(),void e.stopPropagation();var t,n=g(this),i=n.data("value"),s=n.children("a").html(),a=n.data("option"),o=l.find("option");l[0].multiple?(n.addClass("d-none"),u.append(r._addTag(s,n))):(h.find("li.active").removeClass("active").removeClass(c.clsOptionActive),n.addClass("active").addClass(c.clsOptionActive),u.html(s),v.getPlugin(d,"dropdown").close()),g.each(o,function(){this===a&&(this.selected=!0)}),w.exec(c.onItemSelect,[i,a,n[0]],l[0]),l.fire("itemselect",{val:i,option:a,leaf:n[0]}),t=r.getSelected(),w.exec(c.onChange,[t],l[0]),l.fire("change",{selected:t})}),u.on("click",".tag .remover",function(e){var t,n=g(this).closest(".tag"),i=n.data("option"),s=i.data("option");i.removeClass("d-none"),g.each(l.find("option"),function(){this===s&&(this.selected=!1)}),n.remove(),w.exec(c.onItemDeselect,[s],l[0]),l.fire("itemdeselect",{option:s}),t=r.getSelected(),w.exec(c.onChange,[t],l[0]),l.fire("change",{selected:t}),e.preventDefault(),e.stopPropagation()}),t.on(v.events.keyup,function(){var e,t=this.value.toUpperCase(),n=h.find("li");for(e=0;e<n.length;e++)g(n[e]).hasClass("group-title")||(-1<n[e].getElementsByTagName("a")[0].innerHTML.toUpperCase().indexOf(t)?n[e].style.display="":n[e].style.display="none")}),t.on(v.events.click,function(e){e.preventDefault(),e.stopPropagation()}),d.on(v.events.click,function(e){e.preventDefault(),e.stopPropagation()})},disable:function(){this.element.data("disabled",!0),this.element.closest(".select").addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.closest(".select").removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},reset:function(e){var t,n=this.element,i=this.options,s=n.find("option"),a=n.closest(".select");g.each(s,function(){this.selected=!w.isNull(e)&&this.defaultSelected}),this.list.find("li").remove(),a.find(".select-input").html(""),this._createOptions(),t=this.getSelected(),w.exec(i.onChange,[t],n[0]),n.fire("change",{selected:t})},getSelected:function(){var e=this.element,t=[];return e.find("option").each(function(){this.selected&&t.push(this.value)}),t},val:function(e){var t,n,i,s,a,o,r=this.element,l=this.options,c=r.siblings(".select-input"),d=r.find("option"),u=this.list.find("li"),h=[],p=void 0!==r.attr("multiple");if(w.isNull(e))return g.each(d,function(){this.selected&&h.push(this.value)}),p?h:h[0];g.each(d,function(){this.selected=!1}),u.removeClass("active"),c.html(""),!1===Array.isArray(e)&&(e=[e]),g.each(e,function(){for(n=0;n<d.length;n++)if(t=d[n],i=w.isValue(t.getAttribute("data-template"))?t.getAttribute("data-template").replace("$1",t.text):t.text,""+t.value==""+this){t.selected=!0;break}for(n=0;n<u.length;n++)if(s=g(u[n]),""+s.attr("data-value")==""+this){p?(s.addClass("d-none"),(a=g("<div>").addClass("tag").addClass(l.clsSelectedItem).html("<span class='title'>"+i+"</span>").appendTo(c)).data("option",s),g("<span>").addClass("remover").addClass(l.clsSelectedItemRemover).html("&times;").appendTo(a)):(s.addClass("active"),c.html(i));break}}),o=this.getSelected(),w.exec(l.onChange,[o],r[0]),r.fire("change",{selected:o})},data:function(e,t,n){var i,s,a=this.element,o=n||",";s="string"==typeof t?t.toArray(o).map(function(e){return+e}):Array.isArray(t)?t.slice().map(function(e){return+e}):[],a.empty(),"string"==typeof e?a.html(e):w.isObject(e)&&g.each(e,function(e,t){if(w.isObject(t))i=g("<optgroup label=''>").attr("label",e).appendTo(a),g.each(t,function(e,t){var n=g("<option>").attr("value",e).text(t).appendTo(i);-1<s.indexOf(+e)&&n.prop("selected",!0)});else{var n=g("<option>").attr("value",e).text(t).appendTo(a);-1<s.indexOf(+e)&&n.prop("selected",!0)}}),this._createOptions()},changeAttribute:function(e){"disabled"===e&&this.toggleState()},destroy:function(){var e=this.element,t=e.closest(".select"),n=t.find(".drop-container"),i=e.siblings(".select-input"),s=n.find("input"),a=n.find("ul"),o=t.find(".input-clear-button");return t.off(v.events.click),t.off(v.events.click,".input-clear-button"),i.off(v.events.click),s.off(v.events.blur),s.off(v.events.focus),a.off(v.events.click,"li"),s.off(v.events.keyup),n.off(v.events.click),o.off(v.events.click),n.data("dropdown").destroy(),e}}),g(document).on(v.events.click,function(){g(".select").removeClass("focused")},{ns:"blur-select-elements"})}(Metro,m4q),function(a,o){"use strict";var r=a.utils,n={menuScrollbar:!1,sidebarDeferred:0,shadow:!0,position:"left",size:290,shift:null,staticShift:null,toggle:null,duration:METRO_ANIMATION_DURATION,static:null,menuItemClick:!0,onOpen:a.noop,onClose:a.noop,onToggle:a.noop,onStaticSet:a.noop,onStaticLoss:a.noop,onSidebarCreate:a.noop};a.sidebarSetup=function(e){n=o.extend({},n,e)},window.metroSidebarSetup,a.sidebarSetup(window.metroSidebarSetup),a.Component("sidebar",{init:function(e,t){return this._super(t,e,n,{toggle_element:null,id:r.elementId("sidebar")}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),o(window).resize(),this._checkStatic(),this._fireEvent("sidebar-create",{element:e})},_createStructure:function(){var e=this.element,t=this.options,n=e.find(".sidebar-header"),i=a.sheet,s=e.find(".sidebar-menu");e.addClass("sidebar").addClass("on-"+t.position),!1===t.menuScrollbar&&s.addClass("hide-scroll"),290!==t.size&&(r.addCssRule(i,".sidebar","width: "+t.size+"px;"),"left"===t.position?r.addCssRule(i,".sidebar.on-left","left: "+-t.size+"px;"):r.addCssRule(i,".sidebar.on-right","right: "+-t.size+"px;")),!0===t.shadow&&e.addClass("sidebar-shadow"),null!==t.toggle&&0<o(t.toggle).length&&(this.toggle_element=o(t.toggle)),0<n.length&&void 0!==n.data("image")&&n.css({backgroundImage:"url("+n.data("image")+")"}),null!==t.static&&null!==t.staticShift&&("left"===t.position?r.addCssRule(i,"@media screen and "+a.media_queries[t.static.toUpperCase()],t.staticShift+"{margin-left: "+t.size+"px; width: calc(100% - "+t.size+"px);}"):r.addCssRule(i,"@media screen and "+a.media_queries[t.static.toUpperCase()],t.staticShift+"{margin-right: "+t.size+"px; width: calc(100% - "+t.size+"px);}"))},_createEvents:function(){var t=this,e=this.element,n=this.options,i=this.toggle_element;null!==i?i.on(a.events.click,function(e){t.toggle(),e.stopPropagation()}):n.toggle&&o.document().on("click",n.toggle,function(e){t.toggle(),e.stopPropagation()}),null!==n.static&&-1<["fs","sm","md","lg","xl","xxl"].indexOf(n.static)&&o(window).on(a.events.resize,function(){t._checkStatic()},{ns:this.id}),!0===n.menuItemClick&&e.on(a.events.click,".sidebar-menu li > a",function(e){t.close(),e.stopPropagation()}),e.on(a.events.click,".sidebar-menu .js-sidebar-close",function(e){t.close(),e.stopPropagation()}),e.on(a.events.click,function(e){e.stopPropagation()})},_checkStatic:function(){var e=this.element,t=this.options;r.mediaExist(t.static)&&!e.hasClass("static")&&(e.addClass("static"),e.data("opened",!1).removeClass("open"),null!==t.shift&&o.each(t.shift.split(","),function(){o(this).animate({draw:{left:0},dur:t.duration})}),r.exec(t.onStaticSet,null,e[0]),e.fire("staticset")),r.mediaExist(t.static)||(e.removeClass("static"),r.exec(t.onStaticLoss,null,e[0]),e.fire("staticloss"))},isOpen:function(){return!0===this.element.data("opened")},open:function(){var e=this.element,t=this.options;e.hasClass("static")||(e.data("opened",!0).addClass("open"),null!==t.shift&&o(t.shift).animate({draw:{left:e.outerWidth()},dur:t.duration}),r.exec(t.onOpen,null,e[0]),e.fire("open"))},close:function(){var e=this.element,t=this.options;e.hasClass("static")||(e.data("opened",!1).removeClass("open"),null!==t.shift&&o(t.shift).animate({draw:{left:0},dur:t.duration}),r.exec(t.onClose,null,e[0]),e.fire("close"))},toggle:function(){this.isOpen()?this.close():this.open(),r.exec(this.options.onToggle,null,this.element[0]),this.element.fire("toggle")},changeAttribute:function(){},destroy:function(){var e=this.element,t=this.options,n=this.toggle_element;return null!==n&&n.off(a.events.click),null!==t.static&&-1<["fs","sm","md","lg","xl","xxl"].indexOf(t.static)&&o(window).off(a.events.resize,{ns:this.id}),!0===t.menuItemClick&&e.off(a.events.click,".sidebar-menu li > a"),e.off(a.events.click,".sidebar-menu .js-sidebar-close"),e}}),a.sidebar={isSidebar:function(e){return r.isMetroObject(e,"sidebar")},open:function(e){this.isSidebar(e)&&a.getPlugin(e,"sidebar").open()},close:function(e){this.isSidebar(e)&&a.getPlugin(e,"sidebar").close()},toggle:function(e){this.isSidebar(e)&&a.getPlugin(e,"sidebar").toggle()},isOpen:function(e){if(this.isSidebar(e))return a.getPlugin(e,"sidebar").isOpen()}}}(Metro,m4q),function(h,p){"use strict";var c=h.utils,n={sliderDeferred:0,roundValue:!0,min:0,max:100,accuracy:0,showMinMax:!1,minMaxPosition:h.position.TOP,value:0,buffer:0,hint:!1,hintAlways:!1,hintPosition:h.position.TOP,hintMask:"$1",vertical:!1,target:null,returnType:"value",size:0,clsSlider:"",clsBackside:"",clsComplete:"",clsBuffer:"",clsMarker:"",clsHint:"",clsMinMax:"",clsMin:"",clsMax:"",onStart:h.noop,onStop:h.noop,onMove:h.noop,onSliderClick:h.noop,onChange:h.noop,onChangeValue:h.noop,onChangeBuffer:h.noop,onFocus:h.noop,onBlur:h.noop,onSliderCreate:h.noop};h.sliderSetup=function(e){n=p.extend({},n,e)},window.metroSliderSetup,h.sliderSetup(window.metroSliderSetup),h.Component("slider",{init:function(e,t){return this._super(t,e,n,{slider:null,value:0,percent:0,pixel:0,buffer:0,keyInterval:!1,id:c.elementId("slider")}),this},_create:function(){var e=this.element,t=this.options;this._createSlider(),this._createEvents(),this.buff(t.buffer),this.val(t.value),this._fireEvent("slider-create",{element:e})},_createSlider:function(){var e,t=this.element,n=this.options,i=t.prev(),s=t.parent(),a=p("<div>").addClass("slider "+t[0].className).addClass(n.clsSlider),o=p("<div>").addClass("backside").addClass(n.clsBackside),r=p("<div>").addClass("complete").addClass(n.clsComplete),l=p("<div>").addClass("buffer").addClass(n.clsBuffer),c=p("<button>").attr("type","button").addClass("marker").addClass(n.clsMarker),d=p("<div>").addClass("hint").addClass(n.hintPosition+"-side").addClass(n.clsHint);if(0<n.size&&(!0===n.vertical?a.outerHeight(n.size):a.outerWidth(n.size)),!0===n.vertical&&a.addClass("vertical-slider"),0===i.length?s.prepend(a):a.insertAfter(i),!0===n.hintAlways&&d.css({display:"block"}).addClass("permanent-hint"),t.appendTo(a),o.appendTo(a),r.appendTo(a),l.appendTo(a),c.appendTo(a),d.appendTo(c),!0===n.showMinMax){var u=p("<div>").addClass("slider-min-max clear").addClass(n.clsMinMax);p("<span>").addClass("place-left").addClass(n.clsMin).html(n.min).appendTo(u),p("<span>").addClass("place-right").addClass(n.clsMax).html(n.max).appendTo(u),n.minMaxPosition===h.position.TOP?u.insertBefore(a):u.insertAfter(a)}if(!(t[0].className="")===n.copyInlineStyles)for(e=0;e<t[0].style.length;e++)a.css(t[0].style[e],t.css(t[0].style[e]));t.is(":disabled")?this.disable():this.enable(),this.slider=a},_createEvents:function(){var i=this,e=this.slider,s=this.options,t=e.find(".marker"),n=e.find(".hint");t.on(h.events.startAll,function(){!0===s.hint&&!0!==s.hintAlways&&n.fadeIn(300),p(document).on(h.events.moveAll,function(e){i._move(e),i._fireEvent("move",{val:i.value,percent:i.percent})},{ns:i.id,passive:!1}),p(document).on(h.events.stopAll,function(){p(document).off(h.events.moveAll,{ns:i.id}),p(document).off(h.events.stopAll,{ns:i.id}),!0!==s.hintAlways&&n.fadeOut(300),i._fireEvent("stop",{val:i.value,percent:i.percent})},{ns:i.id}),i._fireEvent("start",{val:i.value,percent:i.percent})}),t.on(h.events.focus,function(){i._fireEvent("focus",{val:i.value,percent:i.percent})}),t.on(h.events.blur,function(){i._fireEvent("blur",{val:i.value,percent:i.percent})}),t.on(h.events.keydown,function(t){var e=t.keyCode?t.keyCode:t.which;if(-1!==[37,38,39,40].indexOf(e)){var n=0===s.accuracy?1:s.accuracy;i.keyInterval||(i.keyInterval=setInterval(function(){var e=i.value;37!==t.keyCode&&40!==t.keyCode||(e-n<s.min?e=s.min:e-=n),38!==t.keyCode&&39!==t.keyCode||(e+n>s.max?e=s.max:e+=n),i.value=i._correct(e),i.percent=i._convert(i.value,"val2prc"),i.pixel=i._convert(i.percent,"prc2pix"),i._redraw()},100),t.preventDefault())}}),t.on(h.events.keyup,function(){clearInterval(i.keyInterval),i.keyInterval=!1}),e.on(h.events.click,function(e){i._move(e),i._fireEvent("slider-click",{val:i.value,percent:i.percent}),i._fireEvent("stop",{val:i.value,percent:i.percent})}),p(window).on(h.events.resize,function(){i.val(i.value),i.buff(i.buffer)},{ns:i.id})},_convert:function(e,t){var n=this.slider,i=this.options,s=(!0===i.vertical?n.outerHeight():n.outerWidth())-n.find(".marker").outerWidth();switch(t){case"pix2prc":return 100*e/s;case"pix2val":return this._convert(e,"pix2prc")*((i.max-i.min)/100)+i.min;case"val2prc":return(e-i.min)/((i.max-i.min)/100);case"prc2pix":return e/(100/s);case"val2pix":return this._convert(this._convert(e,"val2prc"),"prc2pix")}return 0},_correct:function(e){var t=e,n=this.options.accuracy,i=this.options.min,s=this.options.max;return 0===n||isNaN(n)?t:((t=Math.round(e/n)*n)<i&&(t=i),s<t&&(t=s),t.toFixed(c.decCount(n)))},_move:function(e){var t,n,i=this.slider,s=this.options,a=i.offset(),o=i.find(".marker").outerWidth(),r=!0===s.vertical?i.outerHeight():i.outerWidth(),l=r-o;t=!0===s.vertical?c.pageXY(e).y-a.top:c.pageXY(e).x-a.left,(n=!0===s.vertical?r-t-o/2:t-o/2)<0||l<n||(this.value=this._correct(this._convert(n,"pix2val")),this.percent=this._convert(this.value,"val2prc"),this.pixel=this._convert(this.percent,"prc2pix"),this._redraw())},_hint:function(){var e=this.options,t=this.slider.find(".hint"),n=+this.value||0,i=+this.percent||0;e.roundValue&&(n=(c.isValue(n)?+n:0).toFixed(c.decCount(e.accuracy)),i=(c.isValue(i)?+i:0).toFixed(c.decCount(e.accuracy))),t.text(e.hintMask.replace("$1",n).replace("$2",i))},_value:function(){var e=this.element,t=this.options,n="value"===t.returnType?this.value:this.percent,i=this.percent,s=this.buffer;if(t.roundValue&&(n=(c.isValue(n)?+n:0).toFixed(c.decCount(t.accuracy)),i=(c.isValue(i)?+i:0).toFixed(c.decCount(t.accuracy)),s=(c.isValue(s)?+s:0).toFixed(c.decCount(t.accuracy))),"INPUT"===e[0].tagName&&e.val(n),null!==t.target){var a=p(t.target);0!==a.length&&p.each(a,function(){var e=p(this);"INPUT"===this.tagName?e.val(n):e.text(n),e.trigger("change")})}this._fireEvent("change-value",{val:n}),this._fireEvent("change",{val:n,percent:i,buffer:s})},_marker:function(){var e=this.slider,t=this.options,n=e.find(".marker"),i=e.find(".complete"),s=!0===t.vertical?e.outerHeight():e.outerWidth(),a=parseInt(c.getStyleOne(n,"width")),o=c.isVisible(e);o&&n.css({"margin-top":0,"margin-left":0}),!0===t.vertical?(o?n.css("top",s-this.pixel):(n.css("top",100-this.percent+"%"),n.css("margin-top",a/2)),i.css("height",this.percent+"%")):(o?n.css("left",this.pixel):(n.css("left",this.percent+"%"),n.css("margin-left",0===this.percent?0:-1*a/2)),i.css("width",this.percent+"%"))},_redraw:function(){this._marker(),this._value(),this._hint()},_buffer:function(){var e=this.element,t=this.options,n=this.slider.find(".buffer");!0===t.vertical?n.css("height",this.buffer+"%"):n.css("width",this.buffer+"%"),this._fireEvent("change-buffer",{val:this.buffer}),this._fireEvent("change",{val:e.val(),percent:this.percent,buffer:this.buffer})},val:function(e){var t=this.options;if(void 0===e||isNaN(e))return this.value;e<t.min&&(e=t.min),e>t.max&&(e=t.max),this.value=this._correct(e),this.percent=this._convert(this.value,"val2prc"),this.pixel=this._convert(this.percent,"prc2pix"),this._redraw()},buff:function(e){var t=this.slider.find(".buffer");return void 0===e||isNaN(e)?this.buffer:0!==t.length&&(100<(e=parseInt(e))&&(e=100),e<0&&(e=0),this.buffer=e,void this._buffer())},changeValue:function(){var e=this.element,t=this.options,n=e.attr("data-value");n<t.min&&(n=t.min),n>t.max&&(n=t.max),this.val(n)},changeBuffer:function(){var e=this.element,t=parseInt(e.attr("data-buffer"));t<0&&(t=0),100<t&&(t=100),this.buff(t)},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},changeAttribute:function(e){switch(e){case"data-value":this.changeValue();break;case"data-buffer":this.changeBuffer();break;case"disabled":this.toggleState()}},destroy:function(){var e=this.element,t=this.slider,n=t.find(".marker");return n.off(h.events.startAll),n.off(h.events.focus),n.off(h.events.blur),n.off(h.events.keydown),n.off(h.events.keyup),t.off(h.events.click),p(window).off(h.events.resize,{ns:this.id}),e}})}(Metro,m4q),function(n,r){"use strict";var l=n.utils,i={sorterDeferred:0,thousandSeparator:",",decimalSeparator:",",sortTarget:null,sortSource:null,sortDir:"asc",sortStart:!0,saveInitial:!0,onSortStart:n.noop,onSortStop:n.noop,onSortItemSwitch:n.noop,onSorterCreate:n.noop};n.sorterSetup=function(e){i=r.extend({},i,e)},window.metroSorterSetup,n.sorterSetup(window.metroSorterSetup),n.Component("sorter",{init:function(e,t){return this._super(t,e,i,{initial:[]}),this},_create:function(){var e=this.element;this._createStructure(),this._fireEvent("sorter-create",{element:e})},_createStructure:function(){var e=this.element,t=this.options;null===t.sortTarget&&(t.sortTarget=e.children()[0].tagName),this.initial=e.find(t.sortTarget).get(),!0===t.sortStart&&this.sort(t.sortDir)},_getItemContent:function(e){var t,n,i,s,a=this.options;if(l.isValue(a.sortSource)){if(t="",0<(n=e.getElementsByClassName(a.sortSource)).length)for(i=0;i<n.length;i++)t+=n[i].textContent;s=n[0].dataset.format}else t=e.textContent,s=e.dataset.format;if(t=(""+t).toLowerCase().replace(/[\n\r]+|[\s]{2,}/g," ").trim(),l.isValue(s))switch(-1===["number","int","float","money"].indexOf(s)||","===a.thousandSeparator&&"."===a.decimalSeparator||(t=l.parseNumber(t,a.thousandSeparator,a.decimalSeparator)),s){case"date":t=l.isDate(t)?new Date(t):"";break;case"number":t=Number(t);break;case"int":t=parseInt(t);break;case"float":t=parseFloat(t);break;case"money":t=l.parseMoney(t);break;case"card":t=l.parseCard(t);break;case"phone":t=l.parsePhone(t)}return t},sort:function(e){var t,n,a=this,i=this.element,s=this.options,o=l.elementId("temp");void 0!==e&&(s.sortDir=e),0!==(t=i.find(s.sortTarget).get()).length&&(n=r("<div>").attr("id",o).insertBefore(r(i.find(s.sortTarget)[0])),this._fireEvent("sort-start",{items:t}),t.sort(function(e,t){var n=a._getItemContent(e),i=a._getItemContent(t),s=0;return n<i&&(s=-1),i<n&&(s=1),0!==s&&a._fireEvent("sort-item-switch",{a:e,b:t,result:s}),s}),"desc"===s.sortDir&&t.reverse(),i.find(s.sortTarget).remove(),r.each(t,function(){var e=r(this);e.insertAfter(n),n=e}),r("#"+o).remove(),this._fireEvent("sort-stop",{items:t}))},reset:function(){var e,t,n=this.element,i=this.options,s=l.elementId("sorter");0!==(e=this.initial).length&&(t=r("<div>").attr("id",s).insertBefore(r(n.find(i.sortTarget)[0])),n.find(i.sortTarget).remove(),r.each(e,function(){var e=r(this);e.insertAfter(t),t=e}),r("#"+s).remove())},changeAttribute:function(e){var t,n,i=this,s=this.element,a=this.options;switch(e){case"data-sort-dir":""!==(n=s.attr("data-sort-dir").trim())&&(a.sortDir=n,i.sort());break;case"data-sort-content":""!==(t=s.attr("data-sort-content").trim())&&(a.sortContent=t,i.sort())}},destroy:function(){return this.element}}),n.sorter={create:function(e,t){return l.$()(e).sorter(t)},isSorter:function(e){return l.isMetroObject(e,"sorter")},sort:function(e,t){if(!this.isSorter(e))return!1;void 0===t&&(t="asc"),n.getPlugin(e,"sorter").sort(t)},reset:function(e){if(!this.isSorter(e))return!1;n.getPlugin(e,"sorter").reset()}}}(Metro,m4q),function(i,c){"use strict";var d=i.utils,n={spinnerDeferred:0,step:1,plusIcon:"<span class='default-icon-plus'></span>",minusIcon:"<span class='default-icon-minus'></span>",buttonsPosition:"default",defaultValue:0,minValue:null,maxValue:null,fixed:0,repeatThreshold:1e3,hideCursor:!1,clsSpinner:"",clsSpinnerInput:"",clsSpinnerButton:"",clsSpinnerButtonPlus:"",clsSpinnerButtonMinus:"",onBeforeChange:i.noop_true,onChange:i.noop,onPlusClick:i.noop,onMinusClick:i.noop,onArrowUp:i.noop,onArrowDown:i.noop,onButtonClick:i.noop,onArrowClick:i.noop,onSpinnerCreate:i.noop};i.spinnerSetup=function(e){n=c.extend({},n,e)},window.metroSpinnerSetup,i.spinnerSetup(window.metroSpinnerSetup),i.Component("spinner",{init:function(e,t){return this._super(t,e,n,{repeat_timer:!1}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("spinner-create",{element:e})},_createStructure:function(){var e=this.element,t=this.options,n=c("<div>").addClass("spinner").addClass("buttons-"+t.buttonsPosition).addClass(e[0].className).addClass(t.clsSpinner),i=c("<button>").attr("type","button").addClass("button spinner-button spinner-button-plus").addClass(t.clsSpinnerButton+" "+t.clsSpinnerButtonPlus).html(t.plusIcon),s=c("<button>").attr("type","button").addClass("button spinner-button spinner-button-minus").addClass(t.clsSpinnerButton+" "+t.clsSpinnerButtonMinus).html(t.minusIcon),a=e.val().trim();d.isValue(a)||e.val(0),e[0].className="",n.insertBefore(e),e.appendTo(n).addClass(t.clsSpinnerInput),e.addClass("original-input"),i.appendTo(n),s.appendTo(n),!0===t.hideCursor&&n.addClass("hide-cursor"),!0===t.disabled||e.is(":disabled")?this.disable():this.enable()},_createEvents:function(){var a=this,o=this.element,r=this.options,t=o.closest(".spinner"),e=t.find(".spinner-button"),l=function(e,t){var n=o.val(),i=Number(o.val()),s=Number(r.step);e?i+=s:i-=s,a._setValue(i.toFixed(r.fixed),!0),d.exec(e?r.onPlusClick:r.onMinusClick,[n,i,o.val()],o[0]),o.fire(e?"plusclick":"minusclick",{curr:n,val:i,elementVal:o.val()}),d.exec(e?r.onArrowUp:r.onArrowDown,[n,i,o.val()],o[0]),o.fire(e?"arrowup":"arrowdown",{curr:n,val:i,elementVal:o.val()}),d.exec(r.onButtonClick,[n,i,o.val(),e?"plus":"minus"],o[0]),o.fire("buttonclick",{button:e?"plus":"minus",curr:n,val:i,elementVal:o.val()}),d.exec(r.onArrowClick,[n,i,o.val(),e?"plus":"minus"],o[0]),o.fire("arrowclick",{button:e?"plus":"minus",curr:n,val:i,elementVal:o.val()}),setTimeout(function(){a.repeat_timer&&l(e,100)},t)};t.on(i.events.click,function(e){c(".focused").removeClass("focused"),t.addClass("focused"),e.preventDefault(),e.stopPropagation()}),e.on(i.events.start,function(e){var t=c(this).closest(".spinner-button").hasClass("spinner-button-plus");e.preventDefault(),a.repeat_timer=!0,l(t,r.repeatThreshold)}),e.on(i.events.stop,function(){a.repeat_timer=!1}),o.on(i.events.keydown,function(e){e.keyCode!==i.keyCode.UP_ARROW&&e.keyCode!==i.keyCode.DOWN_ARROW||(a.repeat_timer=!0,l(e.keyCode===i.keyCode.UP_ARROW,r.repeatThreshold))}),t.on(i.events.keyup,function(){a.repeat_timer=!1})},_setValue:function(e,t){var n=this.element,i=this.options;!0===d.exec(i.onBeforeChange,[e],n[0])&&(d.isValue(i.maxValue)&&e>Number(i.maxValue)&&(e=Number(i.maxValue)),d.isValue(i.minValue)&&e<Number(i.minValue)&&(e=Number(i.minValue)),n.val(e),d.exec(i.onChange,[e],n[0]),!0===t&&n.fire("change",{val:e}))},val:function(e){var t=this.element,n=this.options;if(!d.isValue(e))return t.val();this._setValue(e.toFixed(n.fixed),!0)},toDefault:function(){var e=this.element,t=this.options,n=d.isValue(t.defaultValue)?Number(t.defaultValue):0;this._setValue(n.toFixed(t.fixed),!0),d.exec(t.onChange,[n],e[0]),e.fire("change",{val:n})},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},changeAttribute:function(e){var t,n=this,i=this.element;switch(e){case"disabled":this.toggleState();break;case"value":t=i.attr("value").trim(),d.isValue(t)&&n._setValue(Number(t),!1)}},destroy:function(){var e=this.element,t=e.closest(".spinner"),n=t.find(".spinner-button");return t.off(i.events.click),n.off(i.events.start),n.off(i.events.stop),e.off(i.events.keydown),t.off(i.events.keyup),e}}),c(document).on(i.events.click,function(){c(".spinner").removeClass("focused")})}(Metro,m4q),function(p,f){"use strict";var m=p.utils,n=p.storage,i={splitterDeferred:0,splitMode:"horizontal",splitSizes:null,gutterSize:4,minSizes:null,children:"*",gutterClick:"expand",saveState:!1,onResizeStart:p.noop,onResizeStop:p.noop,onResizeSplit:p.noop,onResizeWindow:p.noop,onSplitterCreate:p.noop};p.splitterSetup=function(e){i=f.extend({},i,e)},window.metroSplitterSetup,p.splitterSetup(window.metroSplitterSetup),p.Component("splitter",{init:function(e,t){return this._super(t,e,i,{storage:m.isValue(n)?n:null,storageKey:"SPLITTER:",id:m.elementId("splitter")}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("splitter-create",{element:e})},_createStructure:function(){var e,t=this.element,n=this.options,i=t.children(n.children).addClass("split-block"),s=[],a="horizontal"===n.splitMode?"width":"height";for(t.addClass("splitter"),"vertical"===n.splitMode.toLowerCase()&&t.addClass("vertical"),e=0;e<i.length-1;e++)f("<div>").addClass("gutter").css(a,n.gutterSize).insertAfter(f(i[e]));if(this._setSize(),m.isValue(n.minSizes))if(String(n.minSizes).contains(","))for(s=n.minSizes.toArray(),e=0;e<s.length;e++)f(i[e]).data("min-size",s[e]),i[e].style.setProperty("min-"+a,String(s[e]).contains("%")?s[e]:String(s[e]).replace("px","")+"px","important");else f.each(i,function(){this.style.setProperty("min-"+a,String(n.minSizes).contains("%")?n.minSizes:String(n.minSizes).replace("px","")+"px","important")});n.saveState&&null!==this.storage&&this._getSize()},_setSize:function(){var e,t,n,i=this.element,s=this.options,a=i.children(".split-block");if(e=i.children(".gutter"),m.isValue(s.splitSizes))for(t=s.splitSizes.toArray(),n=0;n<t.length;n++)f(a[n]).css({flexBasis:"calc("+t[n]+"% - "+e.length*s.gutterSize+"px)"});else a.css({flexBasis:"calc("+100/a.length+"% - "+e.length*s.gutterSize+"px)"})},_createEvents:function(){var n=this,d=this.element,u=this.options,h=d.children(".gutter");h.on(p.events.startAll,function(e){var i="horizontal"===u.splitMode?d.width():d.height(),s=f(this),a=s.prev(".split-block"),o=s.next(".split-block"),r=100*("horizontal"===u.splitMode?a.outerWidth(!0):a.outerHeight(!0))/i,l=100*("horizontal"===u.splitMode?o.outerWidth(!0):o.outerHeight(!0))/i,c=m.getCursorPosition(d[0],e);s.addClass("active"),a.addClass("stop-pointer"),o.addClass("stop-pointer"),m.exec(u.onResizeStart,[c,s[0],a[0],o[0]],d[0]),d.fire("resizestart",{pos:c,gutter:s[0],prevBlock:a[0],nextBlock:o[0]}),f(window).on(p.events.moveAll,function(e){var t,n=m.getCursorPosition(d[0],e);t="horizontal"===u.splitMode?100*n.x/i-100*c.x/i:100*n.y/i-100*c.y/i,a.css("flex-basis","calc("+(r+t)+"% - "+h.length*u.gutterSize+"px)"),o.css("flex-basis","calc("+(l-t)+"% - "+h.length*u.gutterSize+"px)"),m.exec(u.onResizeSplit,[n,s[0],a[0],o[0]],d[0]),d.fire("resizesplit",{pos:n,gutter:s[0],prevBlock:a[0],nextBlock:o[0]})},{ns:n.id}),f(window).on(p.events.stopAll,function(e){var t;a.removeClass("stop-pointer"),o.removeClass("stop-pointer"),n._saveSize(),s.removeClass("active"),f(window).off(p.events.moveAll,{ns:n.id}),f(window).off(p.events.stopAll,{ns:n.id}),t=m.getCursorPosition(d[0],e),m.exec(u.onResizeStop,[t,s[0],a[0],o[0]],d[0]),d.fire("resizestop",{pos:t,gutter:s[0],prevBlock:a[0],nextBlock:o[0]})},{ns:n.id})}),f(window).on(p.events.resize,function(){var e=d.children(".gutter"),t=e.prev(".split-block"),n=e.next(".split-block");m.exec(u.onResizeWindow,[t[0],n[0]],d[0]),d.fire("resizewindow",{prevBlock:t[0],nextBlock:n[0]})},{ns:n.id})},_saveSize:function(){var e=this.element,t=this.options,n=this.storage,i=[],s=e.attr("id")||this.id;!0===t.saveState&&null!==n&&(f.each(e.children(".split-block"),function(){var e=f(this);i.push(e.css("flex-basis"))}),n&&n.setItem(this.storageKey+s,i))},_getSize:function(){var e=this.element,t=this.options,n=this.storage,i=[],s=e.attr("id")||this.id;!0===t.saveState&&null!==n&&(i=n.getItem(this.storageKey+s),f.each(e.children(".split-block"),function(e,t){var n=f(t);m.isValue(i)&&m.isValue(i[e])&&n.css("flex-basis",i[e])}))},size:function(e){var t=this.options;return m.isValue(e)&&(t.splitSizes=e,this._setSize()),this},changeAttribute:function(e){var t,n=this,i=this.element;"data-split-sizes"===e&&(t=i.attr("data-split-sizes"),n.size(t))},destroy:function(){var e=this.element;return e.children(".gutter").off(p.events.start),e}})}(Metro,m4q),function(s,a){"use strict";var o=s.utils,n={stepperDeferred:0,view:s.stepperView.SQUARE,steps:3,step:1,stepClick:!1,clsStepper:"",clsStep:"",clsComplete:"",clsCurrent:"",onStep:s.noop,onStepClick:s.noop,onStepperCreate:s.noop};s.stepperSetup=function(e){n=a.extend({},n,e)},window.metroStepperSetup,s.stepperSetup(window.metroStepperSetup),s.Component("stepper",{init:function(e,t){return this._super(t,e,n,{current:0}),this},_create:function(){var e=this.element,t=this.options;t.step<=0&&(t.step=1),this._createStepper(),this._createEvents(),this._fireEvent("stepper-create",{element:e})},_createStepper:function(){var e,t=this.element,n=this.options;for(t.addClass("stepper").addClass(n.view).addClass(n.clsStepper),e=1;e<=n.steps;e++)a("<span>").addClass("step").addClass(n.clsStep).data("step",e).html("<span>"+e+"</span>").appendTo(t);this.current=1,this.toStep(n.step)},_createEvents:function(){var t=this,n=this.element,i=this.options;n.on(s.events.click,".step",function(){var e=a(this).data("step");!0===i.stepClick&&(t.toStep(e),o.exec(i.onStepClick,[e],n[0]),n.fire("stepclick",{step:e}))})},next:function(){var e=this.element.find(".step");this.current+1>e.length||(this.current++,this.toStep(this.current))},prev:function(){this.current-1!=0&&(this.current--,this.toStep(this.current))},last:function(){var e=this.element;this.toStep(e.find(".step").length)},first:function(){this.toStep(1)},toStep:function(e){var t=this.element,n=this.options,i=a(t.find(".step").get(e-1));0!==i.length&&(this.current=e,t.find(".step").removeClass("complete current").removeClass(n.clsCurrent).removeClass(n.clsComplete),i.addClass("current").addClass(n.clsCurrent),i.prevAll().addClass("complete").addClass(n.clsComplete),o.exec(n.onStep,[this.current],t[0]),t.fire("step",{step:this.current}))},changeAttribute:function(){},destroy:function(){var e=this.element;return e.off(s.events.click,".step"),e}})}(Metro,m4q),function(e){"use strict";var a=e.utils,t=function(e){return new t.init(e)};t.prototype={setKey:function(e){this.key=e},getKey:function(){return this.key},setItem:function(e,t){this.storage.setItem(this.key+":"+e,JSON.stringify(t))},getItem:function(e,t,n){var i,s;s=this.storage.getItem(this.key+":"+e);try{i=JSON.parse(s,n)}catch(e){i=null}return a.nvl(i,t)},getItemPart:function(e,t,n,i){var s,a=this.getItem(e,n,i);for(t=t.split("->"),s=0;s<t.length;s++)a=a[t[s]];return a},delItem:function(e){this.storage.removeItem(this.key+":"+e)},size:function(e){var t;switch(e){case"m":case"M":t=1048576;break;case"k":case"K":t=1024;break;default:t=1}return JSON.stringify(this.storage).length/t}},t.init=function(e){return this.key="",this.storage=e||window.localStorage,this},t.init.prototype=t.prototype,e.storage=t(window.localStorage),e.session=t(window.sessionStorage)}(Metro),function(M,D){"use strict";var A=M.utils,n={streamerDeferred:0,wheel:!0,wheelStep:20,duration:METRO_ANIMATION_DURATION,defaultClosedIcon:"",defaultOpenIcon:"",changeUri:!0,encodeLink:!0,closed:!1,chromeNotice:!1,startFrom:null,slideToStart:!0,startSlideSleep:1e3,source:null,data:null,eventClick:"select",selectGlobal:!0,streamSelect:!1,excludeSelectElement:null,excludeClickElement:null,excludeElement:null,excludeSelectClass:"",excludeClickClass:"",excludeClass:"",onDataLoad:M.noop,onDataLoaded:M.noop,onDataLoadError:M.noop,onDrawEvent:M.noop,onDrawGlobalEvent:M.noop,onDrawStream:M.noop,onStreamClick:M.noop,onStreamSelect:M.noop,onEventClick:M.noop,onEventSelect:M.noop,onEventsScroll:M.noop,onStreamerCreate:M.noop};M.streamerSetup=function(e){n=D.extend({},n,e)},window.metroStreamerSetup,M.streamerSetup(window.metroStreamerSetup),M.Component("streamer",{init:function(e,t){return this._super(t,e,n,{data:null,scroll:0,scrollDir:"left",events:null}),this},_create:function(){var t=this,n=this.element,i=this.options;if(n.addClass("streamer"),void 0===n.attr("id")&&n.attr("id",A.elementId("streamer")),null===i.source&&null===i.data)return!1;D("<div>").addClass("streams").appendTo(n),D("<div>").addClass("events-area").appendTo(n),null!==i.source?(A.exec(i.onDataLoad,[i.source],n[0]),n.fire("dataload",{source:i.source}),D.json(i.source).then(function(e){A.exec(i.onDataLoaded,[i.source,e],n[0]),n.fire("dataloaded",{source:i.source,data:e}),t.data=e,t.build()},function(e){A.exec(i.onDataLoadError,[i.source,e],n[0]),n.fire("dataloaderror",{source:i.source,xhr:e})})):(this.data=i.data,this.build()),!0===i.chromeNotice&&!0===A.detectChrome()&&!1===A.isTouchDevice()&&D("<p>").addClass("text-small text-muted").html("*) In Chrome browser please press and hold Shift and turn the mouse wheel.").insertAfter(n)},build:function(){var e,t=this,C=this.element,b=this.options,n=this.data,i=C.find(".streams").html(""),s=C.find(".events-area").html(""),y=D("<ul>").addClass("streamer-timeline").html("").appendTo(s),a=D("<div>").addClass("streamer-events").appendTo(s),o=D("<div>").addClass("event-group").appendTo(a),r=A.getURIParameter(null,"StreamerIDS");null!==r&&!0===b.encodeLink&&(r=atob(r));var x=r?r.split("|")[0]:null,S=r?r.split("|")[1].split(","):[];if(void 0!==n.actions){var l=D("<div>").addClass("streamer-actions").appendTo(i);D.each(n.actions,function(){var e=this,t=D("<button>").addClass("streamer-action").addClass(e.cls).html(e.html);void 0!==e.onclick&&t.on(M.events.click,function(){A.exec(e.onclick,[C])}),t.appendTo(l)})}y.html(""),void 0===n.timeline&&(n.timeline={start:"09:00",stop:"18:00",step:20});var c,d,u,h,p,f,m,v,g,w=new Date,T=new Date,k=n.timeline.start?n.timeline.start.split(":"):[9,0],_=n.timeline.stop?n.timeline.stop.split(":"):[18,0],I=n.timeline.step?60*parseInt(n.timeline.step):1200;for(w.setHours(k[0]),w.setMinutes(k[1]),w.setSeconds(0),T.setHours(_[0]),T.setMinutes(_[1]),T.setSeconds(0),c=w.getTime()/1e3;c<=T.getTime()/1e3;c+=I)for(h=((u=(d=new Date(1e3*c)).getHours())<10?"0"+u:u)+":"+((p=d.getMinutes())<10?"0"+p:p),g=(v=D("<li>").data("time",h).addClass("js-time-point-"+h.replace(":","-")).html("<em>"+h+"</em>").appendTo(y)).width()/parseInt(n.timeline.step),e=D("<ul>").addClass("streamer-fake-timeline").html("").appendTo(v),f=0;f<parseInt(n.timeline.step);f++)h=(u<10?"0"+u:u)+":"+((m=p+f)<10?"0"+m:m),D("<li>").data("time",h).addClass("js-fake-time-point-"+h.replace(":","-")).html("|").appendTo(e).css({width:g});if(void 0!==n.streams&&D.each(n.streams,function(f){var m=0,e=D("<div>").addClass("stream").addClass(this.cls).appendTo(i);e.addClass(this.cls).data("one",!1).data("data",this.data),D("<div>").addClass("stream-title").html(this.title).appendTo(e),D("<div>").addClass("stream-secondary").html(this.secondary).appendTo(e),D(this.icon).addClass("stream-icon").appendTo(e);var v=A.computedRgbToHex(A.getStyleOne(e,"background-color")),g=A.computedRgbToHex(A.getStyleOne(e,"color")),w=D("<div>").addClass("stream-events").data("background-color",v).data("text-color",g).appendTo(o);if(void 0!==this.events){D.each(this.events,function(e){var t,n,i=this,s=void 0===i.row?1:parseInt(i.row),a=f+":"+e,o=void 0!==i.custom?i.custom:"",r=void 0!==i.custom_open?i.custom_open:"",l=void 0!==i.custom_close?i.custom_close:"";if(void 0===i.skip||!A.bool(i.skip)){n=D("<div>").data("origin",i).data("sid",a).data("data",i.data).data("time",i.time).data("target",i.target).addClass("stream-event").addClass("size-"+i.size+(["half","one-third"].contains(i.size)?"":"x")).addClass(i.cls).appendTo(w);var c=y.find(".js-fake-time-point-"+this.time.replace(":","-")).offset().left-w.offset().left,d=75*(s-1);if(m<s&&(m=s),n.css({position:"absolute",left:c,top:d}),A.isNull(i.html)){var u=D("<div>").addClass("stream-event-slide").appendTo(n),h=D("<div>").addClass("slide-logo").appendTo(u),p=D("<div>").addClass("slide-data").appendTo(u);void 0!==i.icon&&(A.isTag(i.icon)?D(i.icon).addClass("icon").appendTo(h):D("<img>").addClass("icon").attr("src",i.icon).appendTo(h)),D("<span>").addClass("time").css({backgroundColor:v,color:g}).html(i.time).appendTo(h),D("<div>").addClass("title").html(i.title).appendTo(p),D("<div>").addClass("subtitle").html(i.subtitle).appendTo(p),D("<div>").addClass("desc").html(i.desc).appendTo(p),(!1===b.closed&&C.attr("id")===x&&-1!==S.indexOf(a)||!0===i.selected||1===parseInt(i.selected))&&n.addClass("selected"),!0===b.closed||!0===i.closed||1===parseInt(i.closed)?(t=void 0!==i.closedIcon?A.isTag(i.closedIcon)?i.closedIcon:"<span>"+i.closedIcon+"</span>":A.isTag(b.defaultClosedIcon)?b.defaultClosedIcon:"<span>"+b.defaultClosedIcon+"</span>",D(t).addClass("state-icon").addClass(i.clsClosedIcon).appendTo(u),n.data("closed",!0).data("target",i.target),n.append(r)):(t=void 0!==i.openIcon?A.isTag(i.openIcon)?i.openIcon:"<span>"+i.openIcon+"</span>":A.isTag(b.defaultOpenIcon)?b.defaultOpenIcon:"<span>"+b.defaultOpenIcon+"</span>",D(t).addClass("state-icon").addClass(i.clsOpenIcon).appendTo(u),n.data("closed",!1),n.append(l)),n.append(o)}else n.html(i.html);A.exec(b.onDrawEvent,[n[0]],C[0]),C.fire("drawevent",{event:n[0]})}});var t=w.find(".stream-event").last();0<t.length&&w.outerWidth(t[0].offsetLeft+t.outerWidth())}w.css({height:75*m}),C.find(".stream").eq(w.index()).css({height:75*m}),A.exec(b.onDrawStream,[e[0]],C[0]),C.fire("drawstream",{stream:e[0]})}),void 0!==n.global){var E=a.offset().left;D.each(["before","after"],function(){void 0!==n.global[this]&&D.each(n.global[this],function(){var e=D("<div>").addClass("event-group").addClass("size-"+this.size+(["half","one-third"].contains(this.size)?"":"x")),t=D("<div>").addClass("stream-events global-stream").appendTo(e),n=D("<div>").addClass("stream-event").appendTo(t);n.addClass("global-event").addClass(this.cls).data("time",this.time).data("origin",this).data("data",this.data),D("<div>").addClass("event-title").html(this.title).appendTo(n),D("<div>").addClass("event-subtitle").html(this.subtitle).appendTo(n),D("<div>").addClass("event-html").html(this.html).appendTo(n);var i,s=y.find(".js-fake-time-point-"+this.time.replace(":","-"));0<s.length&&(i=s.offset().left-E),e.css({position:"absolute",left:i,height:"100%"}).appendTo(a),A.exec(b.onDrawGlobalEvent,[n[0]],C[0]),C.fire("dataloaded",{event:n[0]})})})}C.data("stream",-1),C.find(".events-area").scrollLeft(0),this.events=C.find(".stream-event"),this._createEvents(),null!==b.startFrom&&!0===b.slideToStart&&setTimeout(function(){t.slideTo(b.startFrom)},b.startSlideSleep),this._fireEvent("streamer-create",{element:C}),this._fireScroll()},_fireScroll:function(){var e=this.element,t=this.options,n=e.find(".events-area"),i=this.scroll;0!==n.length&&(this.scrollDir=this.scroll<n[0].scrollLeft?"left":"right",this.scroll=n[0].scrollLeft,A.exec(t.onEventsScroll,[n[0].scrollLeft,i,this.scrollDir,D.toArray(this.events)],e[0]),e.fire("eventsscroll",{scrollLeft:n[0].scrollLeft,oldScroll:i,scrollDir:this.scrollDir,events:D.toArray(this.events)}))},_createEvents:function(){var i=this,s=this.element,a=this.options;s.off(M.events.click,".stream-event").on(M.events.click,".stream-event",function(e){var t=D(this);if(!(""!==a.excludeClass&&t.hasClass(a.excludeClass)||null!==a.excludeElement&&D(e.target).is(a.excludeElement)))if(!1===a.closed&&!0!==t.data("closed")&&"select"===a.eventClick)""!==a.excludeSelectClass&&t.hasClass(a.excludeSelectClass)||null!==a.excludeSelectElement&&D(e.target).is(a.excludeSelectElement)||(t.hasClass("global-event")?!0===a.selectGlobal&&t.toggleClass("selected"):t.toggleClass("selected"),!0===a.changeUri&&i._changeURI(),A.exec(a.onEventSelect,[t[0],t.hasClass("selected")],s[0]),s.fire("eventselect",{event:t[0],selected:t.hasClass("selected")}));else if(""!==a.excludeClickClass&&t.hasClass(a.excludeClickClass));else if(null!==a.excludeClickElement&&D(e.target).is(a.excludeClickElement));else if(A.exec(a.onEventClick,[t[0]],s[0]),s.fire("eventclick",{event:t[0]}),!0===a.closed||!0===t.data("closed")){var n=t.data("target");n&&(window.location.href=n)}}),s.off(M.events.click,".stream").on(M.events.click,".stream",function(){var e=D(this),t=e.index();!1!==a.streamSelect&&(s.data("stream")===t?(s.find(".stream-event").removeClass("disabled"),s.data("stream",-1)):(s.data("stream",t),s.find(".stream-event").addClass("disabled"),i.enableStream(e),A.exec(a.onStreamSelect,[e],s[0]),s.fire("streamselect",{stream:e})),A.exec(a.onStreamClick,[e],s[0]),s.fire("streamclick",{stream:e}))}),!0===a.wheel&&(s.find(".events-area").off(M.events.mousewheel).on(M.events.mousewheel,function(e){if(void 0!==e.deltaY){var t,n=D(this),i=0<e.deltaY?-1:1,s=a.wheelStep;t=n.scrollLeft()-i*s,n.scrollLeft(t)}}),s.find(".events-area").off("mouseenter").on("mouseenter",function(){!function(){var e=window.pageYOffset||document.documentElement.scrollTop,t=window.pageXOffset||document.documentElement.scrollLeft;window.onscroll=function(){window.scrollTo(t,e)}}()}),s.find(".events-area").off("mouseleave").on("mouseleave",function(){window.onscroll=function(){}})),s.find(".events-area").last().off("scroll").on("scroll",function(){i._fireScroll()}),!0===A.isTouchDevice()&&s.off(M.events.click,".stream").on(M.events.click,".stream",function(){var e=D(this);e.toggleClass("focused"),D.each(s.find(".stream"),function(){D(this).is(e)||D(this).removeClass("focused")})})},_changeURI:function(){var e=this.getLink();history.pushState({},document.title,e)},slideTo:function(e){var t,n=this.element,i=this.options;t=D(void 0===e?n.find(".streamer-timeline li")[0]:n.find(".streamer-timeline .js-time-point-"+e.replace(":","-"))[0]),n.find(".events-area").animate({draw:{scrollLeft:t[0].offsetLeft-n.find(".streams .stream").outerWidth()},dur:i.duration})},enableStream:function(e){var t=this.element,n=e.index()-1;e.removeClass("disabled").data("streamDisabled",!1),t.find(".stream-events").eq(n).find(".stream-event").removeClass("disabled")},disableStream:function(e){var t=this.element,n=e.index()-1;e.addClass("disabled").data("streamDisabled",!0),t.find(".stream-events").eq(n).find(".stream-event").addClass("disabled")},toggleStream:function(e){!0===e.data("streamDisabled")?this.enableStream(e):this.disableStream(e)},getLink:function(){var e,t=this.element,n=this.options,i=t.find(".stream-event"),s=[],a=window.location.href;return D.each(i,function(){var e=D(this);void 0!==e.data("sid")&&e.hasClass("selected")&&s.push(e.data("sid"))}),e=t.attr("id")+"|"+s.join(","),!0===n.encodeLink&&(e=btoa(e)),A.updateURIParameter(a,"StreamerIDS",e)},getTimes:function(){var e=this.element.find(".streamer-timeline > li"),t=[];return D.each(e,function(){t.push(D(this).data("time"))}),t},getEvents:function(e,n){var t,i=this.element,s=[];switch(e){case"selected":t=i.find(".stream-event.selected");break;case"non-selected":t=i.find(".stream-event:not(.selected)");break;default:t=i.find(".stream-event")}return D.each(t,function(){var e,t=D(this);!0!==n&&t.parent().hasClass("global-stream")||(e=t.data("origin"),s.push(e))}),s},source:function(e){var t=this.element;if(void 0===e)return this.options.source;t.attr("data-source",e),this.options.source=e,this.changeSource()},dataSet:function(e){if(void 0===e)return this.options.data;this.options.data=e,this.changeData(e)},getStreamerData:function(){return this.data},toggleEvent:function(e){var t=this.options;(e=D(e)).hasClass("global-event")&&!0!==t.selectGlobal||(e.hasClass("selected")?this.selectEvent(e,!1):this.selectEvent(e,!0))},selectEvent:function(e,t){var n=this.element,i=this.options;void 0===t&&(t=!0),(e=D(e)).hasClass("global-event")&&!0!==i.selectGlobal||(!0===t?e.addClass("selected"):e.removeClass("selected"),!0===i.changeUri&&this._changeURI(),A.exec(i.onEventSelect,[e[0],t],n[0]),n.fire("eventselect",{event:e[0],selected:t}))},changeSource:function(){var t=this,n=this.element,i=this.options,e=n.attr("data-source");""!==String(e).trim()&&(i.source=e,A.exec(i.onDataLoad,[i.source],n[0]),n.fire("dataload",{source:i.source}),D.json(i.source).then(function(e){A.exec(i.onDataLoaded,[i.source,e],n[0]),n.fire("dataloaded",{source:i.source,data:e}),t.data=e,t.build()},function(e){A.exec(i.onDataLoadError,[i.source,e],n[0]),n.fire("dataloaderror",{source:i.source,xhr:e})}),n.fire("sourcechange"))},changeData:function(e){var t=this.element,n=this.options,i=this.data;n.data="object"==typeof e?e:JSON.parse(t.attr("data-data")),this.data=n.data,this.build(),t.fire("datachange",{oldData:i,newData:n.data})},changeStreamSelectOption:function(){var e=this.element;this.options.streamSelect="true"===e.attr("data-stream-select").toLowerCase()},changeAttribute:function(e){switch(e){case"data-source":this.changeSource();break;case"data-data":this.changeData();break;case"data-stream-select":this.changeStreamSelectOption()}},destroy:function(){var e=this.element;return e.off(M.events.click,".stream-event"),e.off(M.events.click,".stream"),e.find(".events-area").off(M.events.mousewheel),e.find(".events-area").last().off("scroll"),e}})}(Metro,m4q),function(e,a){"use strict";var n={switchDeferred:0,material:!1,transition:!0,caption:"",captionPosition:"right",clsSwitch:"",clsCheck:"",clsCaption:"",onSwitchCreate:e.noop};e.switchSetup=function(e){n=a.extend({},n,e)},window.metroSwitchSetup,e.switchSetup(window.metroSwitchSetup),e.Component("switch",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e=this.element,t=this.options,n=a("<label>").addClass((!0===t.material?" switch-material ":" switch ")+e[0].className),i=a("<span>").addClass("check"),s=a("<span>").addClass("caption").html(t.caption);e.attr("type","checkbox"),void 0!==e.attr("readonly")&&e.on("click",function(e){e.preventDefault()}),n.insertBefore(e),e.appendTo(n),i.appendTo(n),s.appendTo(n),!0===t.transition&&n.addClass("transition-on"),"left"===t.captionPosition&&n.addClass("caption-left"),e[0].className="",n.addClass(t.clsSwitch),s.addClass(t.clsCaption),i.addClass(t.clsCheck),e.is(":disabled")?this.disable():this.enable(),this._fireEvent("switch-create",{element:e})},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},changeAttribute:function(e){switch(e){case"disabled":this.toggleState()}},destroy:function(){return this.element}})}(Metro,m4q),function(w,C){"use strict";var b=w.utils,y=w.export,n={tableDeferred:0,emptyTableTitle:"Nothing to show",templateBeginToken:"<%",templateEndToken:"%>",paginationDistance:5,locale:METRO_LOCALE,horizontalScroll:!1,horizontalScrollStop:null,check:!1,checkType:"checkbox",checkStyle:1,checkColIndex:0,checkName:null,checkStoreKey:"TABLE:$1:KEYS",rownum:!1,rownumTitle:"#",filters:null,filtersOperator:"and",head:null,body:null,static:!1,source:null,searchMinLength:1,searchThreshold:500,searchFields:null,showRowsSteps:!0,showSearch:!0,showTableInfo:!0,showPagination:!0,paginationShortMode:!0,showActivity:!0,muteTable:!0,showSkip:!1,rows:10,rowsSteps:"10,25,50,100",staticView:!1,viewSaveMode:"client",viewSavePath:"TABLE:$1:OPTIONS",sortDir:"asc",decimalSeparator:".",thousandSeparator:",",tableRowsCountTitle:"Show entries:",tableSearchTitle:"Search:",tableInfoTitle:"Showing $1 to $2 of $3 entries",paginationPrevTitle:"Prev",paginationNextTitle:"Next",allRecordsTitle:"All",inspectorTitle:"Inspector",tableSkipTitle:"Go to page",activityType:"cycle",activityStyle:"color",activityTimeout:100,searchWrapper:null,rowsWrapper:null,infoWrapper:null,paginationWrapper:null,skipWrapper:null,cellWrapper:!1,clsComponent:"",clsTableContainer:"",clsTable:"",clsHead:"",clsHeadRow:"",clsHeadCell:"",clsBody:"",clsBodyRow:"",clsBodyCell:"",clsCellWrapper:"",clsFooter:"",clsFooterRow:"",clsFooterCell:"",clsTableTop:"",clsRowsCount:"",clsSearch:"",clsTableBottom:"",clsTableInfo:"",clsTablePagination:"",clsPagination:"",clsTableSkip:"",clsTableSkipInput:"",clsTableSkipButton:"",clsEvenRow:"",clsOddRow:"",clsRow:"",clsEmptyTableTitle:"",onDraw:w.noop,onDrawRow:w.noop,onDrawCell:w.noop,onAppendRow:w.noop,onAppendCell:w.noop,onSortStart:w.noop,onSortStop:w.noop,onSortItemSwitch:w.noop,onSearch:w.noop,onRowsCountChange:w.noop,onDataLoad:w.noop,onDataLoadError:w.noop,onDataLoaded:w.noop,onDataSaveError:w.noop,onFilterRowAccepted:w.noop,onFilterRowDeclined:w.noop,onCheckClick:w.noop,onCheckClickAll:w.noop,onCheckDraw:w.noop,onViewSave:w.noop,onViewGet:w.noop,onViewCreated:w.noop,onTableCreate:w.noop,onSkip:w.noop};w.tableSetup=function(e){n=C.extend({},n,e)},window.metroTableSetup,w.tableSetup(window.metroTableSetup),w.Component("table",{init:function(e,t){return this._super(t,e,n,{currentPage:1,pagesCount:1,searchString:"",data:null,activity:null,loadActivity:null,busy:!1,filters:[],wrapperInfo:null,wrapperSearch:null,wrapperRows:null,wrapperPagination:null,wrapperSkip:null,filterIndex:null,filtersIndexes:[],component:null,inspector:null,view:{},viewDefault:{},locale:w.locales["en-US"],input_interval:null,searchFields:[],id:b.elementId("table"),sort:{dir:"asc",colIndex:0},service:[],heads:[],items:[],foots:[],filteredItems:[],index:{}}),this},_create:function(){var e,t,n,i=this,s=this.element,a=this.options,o=b.elementId("table");if(b.isValue(s.attr("id"))||s.attr("id",o),b.isValue(w.locales[a.locale])&&(this.locale=w.locales[a.locale]),b.isValue(a.searchFields)&&(this.searchFields=a.searchFields.toArray()),b.isValue(a.head)){var r=a.head;a.head=b.isObject(a.head),a.head||(console.warn("Head "+r+" defined but not exists!"),a.head=null)}if(b.isValue(a.body)){var l=a.body;a.body=b.isObject(a.body),a.body||(console.warn("Body "+l+" defined but not exists!"),a.body=null)}if(!0===a.static&&(a.showPagination=!1,a.showRowsSteps=!1,a.showSearch=!1,a.showTableInfo=!1,a.showSkip=!1,a.rows=-1),(e=C("<div>").addClass("table-component")).insertBefore(s),t=C("<div>").addClass("table-container").addClass(a.clsTableContainer).appendTo(e),s.appendTo(t),!0===a.horizontalScroll&&t.addClass("horizontal-scroll"),!b.isNull(a.horizontalScrollStop)&&b.mediaExist(a.horizontalScrollStop)&&t.removeClass("horizontal-scroll"),e.addClass(a.clsComponent),this.activity=C("<div>").addClass("table-progress").appendTo(e),n=C("<div>").appendTo(this.activity),w.makePlugin(n,"activity",{type:a.activityType,style:a.activityStyle}),!0!==a.showActivity&&this.activity.css({visibility:"hidden"}),this.component=e,null!==a.source){b.exec(a.onDataLoad,[a.source],s[0]),s.fire("dataload",{source:a.source});var c=b.isObject(a.source);!1!==c&&C.isPlainObject(c)?i._build(c):this.activity.show(function(){C.json(a.source).then(function(e){if(i.activity.hide(),"object"!=typeof e)throw new Error("Data for table is not a object");b.exec(a.onDataLoaded,[a.source,e],s[0]),s.fire("dataloaded",{source:a.source,data:e}),i._build(e)},function(e){i.activity.hide(),b.exec(a.onDataLoadError,[a.source,e],s[0]),s.fire("dataloaderror",{source:a.source,xhr:e})})})}else i._build()},_createIndex:function(){var n=this,i=this.options.checkColIndex;setImmediate(function(){n.items.forEach(function(e,t){n.index[e[i]]=t})})},_build:function(e){var t,n,i=this,s=this.element,a=this.options,o=s.attr("id");a.rows=parseInt(a.rows),this.items=[],this.heads=[],this.foots=[],Array.isArray(a.head)&&(this.heads=a.head),Array.isArray(a.body)&&(this.items=a.body),b.isValue(e)?this._createItemsFromJSON(e):this._createItemsFromHTML(),this._createIndex(),this.view=this._createView(),this.viewDefault=b.objectClone(this.view),n=a.viewSavePath.replace("$1",o),"client"===a.viewSaveMode.toLowerCase()?(t=w.storage.getItem(n),b.isValue(t)&&b.objectLength(t)===b.objectLength(this.view)&&(this.view=t,b.exec(a.onViewGet,[t],s[0]),s.fire("viewget",{source:"client",view:t})),this._final()):C.json(n,n!==a.viewSavePath?null:{id:o}).then(function(e){b.isValue(e)&&b.objectLength(e)===b.objectLength(i.view)&&(i.view=e,b.exec(a.onViewGet,[e],s[0]),s.fire("viewget",{source:"server",view:e})),i._final()},function(){i._final(),console.warn("Warning! Error loading view for table "+s.attr("id")+" ")})},_final:function(){var e=this.element,t=this.options,n=e.attr("id");w.storage.delItem(t.checkStoreKey.replace("$1",n)),this._service(),this._createStructure(),this._createInspector(),this._createEvents(),this._fireEvent("table-create",{element:e})},_service:function(){var e=this.options;this.service=[{title:e.rownumTitle,format:void 0,name:void 0,sortable:!1,sortDir:void 0,clsColumn:"rownum-cell "+(!0!==e.rownum?"d-none":""),cls:"rownum-cell "+(!0!==e.rownum?"d-none":""),colspan:void 0,type:"rownum"},{title:"checkbox"===e.checkType?"<input type='checkbox' data-role='checkbox' class='table-service-check-all' data-style='"+e.checkStyle+"'>":"",format:void 0,name:void 0,sortable:!1,sortDir:void 0,clsColumn:"check-cell "+(!0!==e.check?"d-none":""),cls:"check-cell "+(!0!==e.check?"d-none":""),colspan:void 0,type:"rowcheck"}]},_createView:function(){var t,e=this.element,n=this.options;return t={},C.each(this.heads,function(e){b.isValue(this.cls)&&(this.cls=this.cls.replace("hidden","")),b.isValue(this.clsColumn)&&(this.clsColumn=this.clsColumn.replace("hidden","")),t[e]={index:e,"index-view":e,show:!b.isValue(this.show)||this.show,size:b.isValue(this.size)?this.size:""}}),b.exec(n.onViewCreated,[t],t),e.fire("viewcreated",{view:t}),t},_createInspectorItems:function(e){var t,n,i=this,s=this.options,a=[],o=this.heads;for(e.html(""),t=0;t<o.length;t++)a[t]=null;for(C.each(o,function(e){(n=C("<tr>")).data("index",e),n.data("index-view",e),C("<td>").html("<input type='checkbox' data-style='"+s.checkStyle+"' data-role='checkbox' name='column_show_check[]' value='"+e+"' "+(b.bool(i.view[e].show)?"checked":"")+">").appendTo(n),C("<td>").html(this.title).appendTo(n),C("<td>").html("<input type='number' data-role='spinner' name='column_size' value='"+i.view[e].size+"' data-index='"+e+"'>").appendTo(n),C("<td>").html("<button class='button square js-table-inspector-field-up' type='button'><span class='mif-arrow-up'></span></button><button class='button square js-table-inspector-field-down' type='button'><span class='mif-arrow-down'></span></button>").appendTo(n),a[i.view[e]["index-view"]]=n}),t=0;t<o.length;t++)a[t].appendTo(e)},_createInspector:function(){var e,t,n,i,s,a=this.options;(e=C("<div data-role='draggable' data-drag-element='.table-inspector-header' data-drag-area='body'>").addClass("table-inspector")).attr("for",this.element.attr("id")),C("<div class='table-inspector-header'>"+a.inspectorTitle+"</div>").appendTo(e),t=C("<div>").addClass("table-wrap").appendTo(e),n=C("<table>").addClass("table subcompact"),i=C("<tbody>").appendTo(n),n.appendTo(t),this._createInspectorItems(i),s=C("<div class='table-inspector-actions'>").appendTo(e),C("<button class='button primary js-table-inspector-save' type='button'>").html(this.locale.buttons.save).appendTo(s),C("<button class='button secondary js-table-inspector-reset ml-2 mr-2' type='button'>").html(this.locale.buttons.reset).appendTo(s),C("<button class='button link js-table-inspector-cancel place-right' type='button'>").html(this.locale.buttons.cancel).appendTo(s),e.data("open",!1),this.inspector=e,C("body").append(e),this._createInspectorEvents()},_resetInspector:function(){var e=this.inspector.find("table tbody");this._createInspectorItems(e),this._createInspectorEvents()},_createHeadsFromHTML:function(){var s=this,e=this.element.find("thead");0<e.length&&C.each(e.find("tr > *"),function(){var e,t,n,i=C(this);e=b.isValue(i.data("sort-dir"))?i.data("sort-dir"):i.hasClass("sort-asc")?"asc":i.hasClass("sort-desc")?"desc":void 0,n=(n=(n=(n=i[0].className.replace("sortable-column","")).replace("sort-asc","")).replace("sort-desc","")).replace("hidden",""),t={type:"data",title:i.html(),name:b.isValue(i.data("name"))?i.data("name"):i.text().replace(" ","_"),sortable:i.hasClass("sortable-column")||b.isValue(i.data("sortable"))&&JSON.parse(!0===i.data("sortable")),sortDir:e,format:b.isValue(i.data("format"))?i.data("format"):"string",formatMask:b.isValue(i.data("format-mask"))?i.data("format-mask"):null,clsColumn:b.isValue(i.data("cls-column"))?i.data("cls-column"):"",cls:n,colspan:i.attr("colspan"),size:b.isValue(i.data("size"))?i.data("size"):"",show:!(i.hasClass("hidden")||b.isValue(i.data("show"))&&!1===JSON.parse(i.data("show"))),required:!!b.isValue(i.data("required"))&&!0===JSON.parse(i.data("required")),field:b.isValue(i.data("field"))?i.data("field"):"input",fieldType:b.isValue(i.data("field-type"))?i.data("field-type"):"text",validator:b.isValue(i.data("validator"))?i.data("validator"):null,template:b.isValue(i.data("template"))?i.data("template"):null},s.heads.push(t)})},_createFootsFromHTML:function(){var n=this,e=this.element.find("tfoot");0<e.length&&C.each(e.find("tr > *"),function(){var e,t=C(this);e={title:t.html(),name:!!b.isValue(t.data("name"))&&t.data("name"),cls:t[0].className,colspan:t.attr("colspan")},n.foots.push(e)})},_createItemsFromHTML:function(){var n=this,e=this.element.find("tbody");0<e.length&&C.each(e.find("tr"),function(){var e=C(this),t=[];C.each(e.children("td"),function(){var e=C(this);t.push(e.html())}),n.items.push(t)}),this._createHeadsFromHTML(),this._createFootsFromHTML()},_createItemsFromJSON:function(e){var t=this;"string"==typeof e&&(e=JSON.parse(e)),void 0!==e.header?t.heads=e.header:this._createHeadsFromHTML(),void 0!==e.data&&C.each(e.data,function(){var e=[];C.each(this,function(){e.push(this)}),t.items.push(e)}),void 0!==e.footer?this.foots=e.footer:this._createFootsFromHTML()},_createTableHeader:function(){var t,i,e,n,s=this.element,a=this.options,o=C("<thead>").html(""),r=[],l=a.staticView?this._createView():this.view;if(s.find("thead").remove(),o.addClass(a.clsHead),0===this.heads.length)return o;for(t=C("<tr>").addClass(a.clsHeadRow).appendTo(o),C.each(this.service,function(){var e=[];i=C("<th>").appendTo(t),b.isValue(this.title)&&i.html(this.title),b.isValue(this.size)&&i.css({width:this.size}),b.isValue(this.cls)&&e.push(this.cls),e.push(a.clsHeadCell),i.addClass(e.join(" "))}),n=this.heads,e=0;e<n.length;e++)r[e]=null;for(C.each(n,function(e){var t=this,n=[];(i=C("<th>")).data("index",e),b.isValue(t.title)&&i.html(t.title),b.isValue(t.format)&&i.attr("data-format",t.format),b.isValue(t.name)&&i.attr("data-name",t.name),b.isValue(t.colspan)&&i.attr("colspan",t.colspan),b.isValue(l[e].size)&&i.css({width:l[e].size}),!0===t.sortable&&(n.push("sortable-column"),b.isValue(t.sortDir)&&n.push("sort-"+t.sortDir)),b.isValue(t.cls)&&C.each(t.cls.toArray(),function(){n.push(this)}),!1===b.bool(l[e].show)&&-1===n.indexOf("hidden")&&n.push("hidden"),n.push(a.clsHeadCell),b.bool(l[e].show)&&b.arrayDelete(n,"hidden"),i.addClass(n.join(" ")),r[l[e]["index-view"]]=i}),e=0;e<n.length;e++)r[e].appendTo(t);s.prepend(o)},_createTableBody:function(){var e,t=this.element;e=t.find("thead"),t.find("tbody").remove(),C("<tbody>").addClass(this.options.clsBody).insertAfter(e)},_createTableFooter:function(){var e,t,n=this.element,i=this.options,s=C("<tfoot>").addClass(i.clsFooter);n.find("tfoot").remove(),0!==this.foots.length&&(e=C("<tr>").addClass(i.clsHeadRow).appendTo(s),C.each(this.foots,function(){t=C("<th>").appendTo(e),void 0!==this.title&&t.html(this.title),void 0!==this.name&&t.addClass("foot-column-name-"+this.name),void 0!==this.cls&&t.addClass(this.cls),b.isValue(this.colspan)&&t.attr("colspan",this.colspan),t.appendTo(e)})),n.append(s)},_createTopBlock:function(){var e,t,n,i,s=this,a=this.element,o=this.options,r=C("<div>").addClass("table-top").addClass(o.clsTableTop).insertBefore(a.parent());return(e=b.isValue(this.wrapperSearch)?this.wrapperSearch:C("<div>").addClass("table-search-block").addClass(o.clsSearch).appendTo(r)).addClass(o.clsSearch),t=C("<input>").attr("type","text").appendTo(e),w.makePlugin(t,"input",{prepend:o.tableSearchTitle}),!0!==o.showSearch&&e.hide(),(n=b.isValue(this.wrapperRows)?this.wrapperRows:C("<div>").addClass("table-rows-block").appendTo(r)).addClass(o.clsRowsCount),i=C("<select>").appendTo(n),C.each(o.rowsSteps.toArray(),function(){var e=parseInt(this),t=C("<option>").attr("value",e).text(-1===e?o.allRecordsTitle:e).appendTo(i);e===parseInt(o.rows)&&t.attr("selected","selected")}),w.makePlugin(i,"select",{filter:!1,prepend:o.tableRowsCountTitle,onChange:function(e){(e=parseInt(e))!==parseInt(o.rows)&&(o.rows=e,s.currentPage=1,s._draw(),b.exec(o.onRowsCountChange,[e],a[0]),a.fire("rowscountchange",{val:e}))}}),!0!==o.showRowsSteps&&n.hide(),r},_createBottomBlock:function(){var e,t,n,i=this.element,s=this.options,a=C("<div>").addClass("table-bottom").addClass(s.clsTableBottom).insertAfter(i.parent());return(e=b.isValue(this.wrapperInfo)?this.wrapperInfo:C("<div>").addClass("table-info").appendTo(a)).addClass(s.clsTableInfo),!0!==s.showTableInfo&&e.hide(),(t=b.isValue(this.wrapperPagination)?this.wrapperPagination:C("<div>").addClass("table-pagination").appendTo(a)).addClass(s.clsTablePagination),!0!==s.showPagination&&t.hide(),(n=b.isValue(this.wrapperSkip)?this.wrapperSkip:C("<div>").addClass("table-skip").appendTo(a)).addClass(s.clsTableSkip),C("<input type='text'>").addClass("input table-skip-input").addClass(s.clsTableSkipInput).appendTo(n),C("<button>").addClass("button table-skip-button").addClass(s.clsTableSkipButton).html(s.tableSkipTitle).appendTo(n),!0!==s.showSkip&&n.hide(),a},_createStructure:function(){var e,t=this,n=this.element,i=this.options,s=C(i.searchWrapper),a=C(i.infoWrapper),o=C(i.rowsWrapper),r=C(i.paginationWrapper),l=C(i.skipWrapper);0<s.length&&(this.wrapperSearch=s),0<a.length&&(this.wrapperInfo=a),0<o.length&&(this.wrapperRows=o),0<r.length&&(this.wrapperPagination=r),0<l.length&&(this.wrapperSkip=l),n.html("").addClass(i.clsTable),this._createTableHeader(),this._createTableBody(),this._createTableFooter(),this._createTopBlock(),this._createBottomBlock();var c,d=!1;0<this.heads.length&&C.each(this.heads,function(e){!d&&-1<["asc","desc"].indexOf(this.sortDir)&&(d=!0,t.sort.colIndex=e,t.sort.dir=this.sortDir)}),d&&(e=n.find("thead th"),this._resetSortClass(e),C(e.get(this.sort.colIndex+t.service.length)).addClass("sort-"+this.sort.dir),this.sorting()),b.isValue(i.filters)&&"string"==typeof i.filters&&C.each(i.filters.toArray(),function(){!1!==(c=b.isFunc(this))&&t.filtersIndexes.push(t.addFilter(c))}),this.currentPage=1,this._draw()},_resetSortClass:function(e){C(e).removeClass("sort-asc sort-desc")},_createEvents:function(){var e,i=this,o=this.element,r=this.options,t=o.closest(".table-component"),n=t.find(".table-container"),s=t.find(".table-search-block input"),a=r.skipWrapper?C(r.skipWrapper).find(".table-skip-button"):t.find(".table-skip-button"),l=r.skipWrapper?C(r.skipWrapper).find(".table-skip-input"):t.find(".table-skip-input"),c=o.attr("id");a.on(w.events.click,function(){var e=parseInt(l.val().trim());if(isNaN(e)||e<=0||e>i.pagesCount)return l.val(""),!1;l.val(""),b.exec(r.onSkip,[e,i.currentPage],o[0]),o.fire("skip",{skipTo:e,skipFrom:i.currentPage}),i.page(e)}),C(window).on(w.events.resize,function(){!0===r.horizontalScroll&&(!b.isNull(r.horizontalScrollStop)&&b.mediaExist(r.horizontalScrollStop)?n.removeClass("horizontal-scroll"):n.addClass("horizontal-scroll"))},{ns:this.id}),o.on(w.events.click,".sortable-column",function(){if(!0===r.muteTable&&o.addClass("disabled"),i.busy)return!1;i.busy=!0;var e=C(this);i.activity.show(function(){setImmediate(function(){i.currentPage=1,i.sort.colIndex=e.data("index"),e.hasClass("sort-asc")||e.hasClass("sort-desc")?e.hasClass("sort-asc")?i.sort.dir="desc":i.sort.dir="asc":i.sort.dir=r.sortDir,i._resetSortClass(o.find(".sortable-column")),e.addClass("sort-"+i.sort.dir),i.sorting(),i._draw(function(){!(i.busy=!1)===r.muteTable&&o.removeClass("disabled")})})})}),o.on(w.events.click,".table-service-check input",function(){var e=C(this),t=e.is(":checked"),n=""+e.val(),i=r.checkStoreKey.replace("$1",c),s=w.storage,a=s.getItem(i);"radio"===e.attr("type")&&(a=[]),t?b.isValue(a)?-1===Array(a).indexOf(n)&&a.push(n):a=[n]:b.isValue(a)?b.arrayDelete(a,n):a=[],s.setItem(i,a),b.exec(r.onCheckClick,[t],this),o.fire("checkclick",{check:this,status:t})}),o.on(w.events.click,".table-service-check-all input",function(){var e=C(this).is(":checked"),t=r.checkStoreKey.replace("$1",c),n=[];e?C.each(i.filteredItems,function(){-1===n.indexOf(this[r.checkColIndex])&&n.push(""+this[r.checkColIndex])}):n=[],w.storage.setItem(t,n),i._draw(),b.exec(r.onCheckClickAll,[e],this),o.fire("checkclickall",{check:this,status:e})});function d(){i.searchString=this.value.trim().toLowerCase(),clearInterval(i.input_interval),i.input_interval=!1,i.input_interval||(i.input_interval=setTimeout(function(){i.currentPage=1,i._draw(),clearInterval(i.input_interval),i.input_interval=!1},r.searchThreshold))}function u(e){var t=C(e),n=t.parent();0!==i.filteredItems.length&&(n.hasClass("active")||(n.hasClass("service")?"prev"===t.data("page")?(i.currentPage--,0===i.currentPage&&(i.currentPage=1)):(i.currentPage++,i.currentPage>i.pagesCount&&(i.currentPage=i.pagesCount)):i.currentPage=t.data("page"),i._draw()))}s.on(w.events.inputchange,d),b.isValue(this.wrapperSearch)&&0<(e=this.wrapperSearch.find("input")).length&&e.on(w.events.inputchange,d),t.on(w.events.click,".pagination .page-link",function(){u(this)}),b.isValue(this.wrapperPagination)&&this.wrapperPagination.on(w.events.click,".pagination .page-link",function(){u(this)}),this._createInspectorEvents(),o.on(w.events.click,".js-table-crud-button",function(){})},_createInspectorEvents:function(){var s=this,e=this.inspector;this._removeInspectorEvents(),e.on(w.events.click,".js-table-inspector-field-up",function(){var t,e=C(this).closest("tr"),n=e.prev("tr"),i=e.data("index");0!==n.length&&(e.insertBefore(n),e.addClass("flash"),setTimeout(function(){e.removeClass("flash")},1e3),t=e.index(),e.data("index-view",t),s.view[i]["index-view"]=t,C.each(e.nextAll(),function(){var e=C(this);t++,e.data("index-view",t),s.view[e.data("index")]["index-view"]=t}),s._createTableHeader(),s._draw())}),e.on(w.events.click,".js-table-inspector-field-down",function(){var t,e=C(this).closest("tr"),n=e.next("tr"),i=e.data("index");0!==n.length&&(e.insertAfter(n),e.addClass("flash"),setTimeout(function(){e.removeClass("flash")},1e3),t=e.index(),e.data("index-view",t),s.view[i]["index-view"]=t,C.each(e.prevAll(),function(){var e=C(this);t--,e.data("index-view",t),s.view[e.data("index")]["index-view"]=t}),s._createTableHeader(),s._draw())}),e.on(w.events.click,"input[type=checkbox]",function(){var e=C(this),t=e.is(":checked"),n=e.val(),i=["cls","clsColumn"];t?C.each(i,function(){var e;e=b.isValue(s.heads[n][this])?s.heads[n][this].toArray(" "):[],b.arrayDelete(e,"hidden"),s.heads[n][this]=e.join(" "),s.view[n].show=!0}):C.each(i,function(){var e;-1===(e=b.isValue(s.heads[n][this])?s.heads[n][this].toArray(" "):[]).indexOf("hidden")&&e.push("hidden"),s.heads[n][this]=e.join(" "),s.view[n].show=!1}),s._createTableHeader(),s._draw()}),e.find("input[type=number]").on(w.events.inputchange,function(){var e=C(this),t=e.attr("data-index"),n=parseInt(e.val());s.view[t].size=0===n?"":n,s._createTableHeader()}),e.on(w.events.click,".js-table-inspector-save",function(){s._saveTableView(),s.openInspector(!1)}),e.on(w.events.click,".js-table-inspector-cancel",function(){s.openInspector(!1)}),e.on(w.events.click,".js-table-inspector-reset",function(){s.resetView()})},_removeInspectorEvents:function(){var e=this.inspector;e.off(w.events.click,".js-table-inspector-field-up"),e.off(w.events.click,".js-table-inspector-field-down"),e.off(w.events.click,"input[type=checkbox]"),e.off(w.events.click,".js-table-inspector-save"),e.off(w.events.click,".js-table-inspector-cancel"),e.off(w.events.click,".js-table-inspector-reset"),e.find("input[type=number]").off(w.events.inputchange)},_saveTableView:function(){var t=this.element,n=this.options,i=this.view,e=t.attr("id"),s=n.viewSavePath.replace("$1",e);if("client"===n.viewSaveMode.toLowerCase())w.storage.setItem(s,i),b.exec(n.onViewSave,[n.viewSavePath,i],t[0]),t.fire("viewsave",{target:"client",path:n.viewSavePath,view:i});else{var a={id:t.attr("id"),view:i};C.post(s,a).then(function(e){b.exec(n.onViewSave,[n.viewSavePath,i,a,e],t[0]),t.fire("viewsave",{target:"server",path:n.viewSavePath,view:i,post_data:a})},function(e){b.exec(n.onDataSaveError,[n.viewSavePath,a,e],t[0]),t.fire("datasaveerror",{source:n.viewSavePath,xhr:e,post_data:a})})}},_info:function(e,t,n){var i,s=this.element,a=this.options,o=s.closest(".table-component"),r=b.isValue(this.wrapperInfo)?this.wrapperInfo:o.find(".table-info");0!==r.length&&(n<t&&(t=n),0===this.items.length&&(e=t=n=0),i=(i=(i=(i=a.tableInfoTitle).replace("$1",e)).replace("$2",t)).replace("$3",n),r.html(i))},_paging:function(e){var t=this.element,n=this.options,i=t.closest(".table-component");this.pagesCount=Math.ceil(e/n.rows),w.pagination({length:e,rows:n.rows,current:this.currentPage,target:b.isValue(this.wrapperPagination)?this.wrapperPagination:i.find(".table-pagination"),claPagination:n.clsPagination,prevTitle:n.paginationPrevTitle,nextTitle:n.paginationNextTitle,distance:!0===n.paginationShortMode?n.paginationDistance:0})},_filter:function(){var e,o=this,r=this.options,l=this.element;return e=b.isValue(this.searchString)&&o.searchString.length>=r.searchMinLength||0<this.filters.length?this.items.filter(function(n){var e,t,i,s="",a=0;if(0<o.filters.length){for(e="and"===r.filtersOperator.toLowerCase(),i=0;i<o.filters.length;i++)b.isNull(o.filters[i])||(a++,e="and"===r.filtersOperator.toLowerCase()?e&&b.exec(o.filters[i],[n,o.heads]):e||b.exec(o.filters[i],[n,o.heads]));0===a&&(e=!0)}else e=!0;return 0<o.searchFields.length?C.each(o.heads,function(e,t){-1<o.searchFields.indexOf(t.name)&&(s+="•"+n[e])}):s=n.join("•"),s=s.replace(/[\n\r]+|[\s]{2,}/g," ").trim().toLowerCase(),t=!(b.isValue(o.searchString)&&o.searchString.length>=r.searchMinLength)||~s.indexOf(o.searchString),(e=e&&t)?(b.exec(r.onFilterRowAccepted,[n],l[0]),l.fire("filterrowaccepted",{row:n})):(b.exec(r.onFilterRowDeclined,[n],l[0]),l.fire("filterrowdeclined",{row:n})),e}):this.items,b.exec(r.onSearch,[o.searchString,e],l[0]),l.fire("search",{search:o.searchString,items:e}),this.filteredItems=e},_draw:function(e){var t,n,i,s,a,o,r,l,c,d=this,u=this.element,h=this.options,p=u.find("tbody"),f=-1===parseInt(h.rows)?0:h.rows*(this.currentPage-1),m=-1===parseInt(h.rows)?this.items.length-1:f+h.rows-1,v=w.storage.getItem(h.checkStoreKey.replace("$1",u.attr("id"))),g=h.staticView?this.viewDefault:this.view;if(p.html(""),this.heads.length){if(0<(c=this._filter()).length){for(t=f;t<=m;t++)if(o=c[t],r=[],b.isValue(o)){for((i=C("<tr>").addClass(h.clsBodyRow)).data("original",o),l=t%2==0,s=C("<td>").html(t+1),void 0!==d.service[0].clsColumn&&s.addClass(d.service[0].clsColumn),s.appendTo(i),s=C("<td>"),a="checkbox"===h.checkType?C("<input type='checkbox' data-style='"+h.checkStyle+"' data-role='checkbox' name='"+(b.isValue(h.checkName)?h.checkName:"table_row_check")+"[]' value='"+c[t][h.checkColIndex]+"'>"):C("<input type='radio' data-style='"+h.checkStyle+"' data-role='radio' name='"+(b.isValue(h.checkName)?h.checkName:"table_row_check")+"' value='"+c[t][h.checkColIndex]+"'>"),b.isValue(v)&&Array.isArray(v)&&-1<v.indexOf(""+c[t][h.checkColIndex])&&a.prop("checked",!0),a.addClass("table-service-check"),b.exec(h.onCheckDraw,[a],a[0]),u.fire("checkdraw",{check:a}),a.appendTo(s),void 0!==d.service[1].clsColumn&&s.addClass(d.service[1].clsColumn),s.appendTo(i),n=0;n<o.length;n++)r[n]=null;for(C.each(o,function(e){var t=this,n=C("<td>");b.isValue(d.heads[e].template)&&(t=d.heads[e].template.replace("%VAL%",t)),n.html(t),n.addClass(h.clsBodyCell),b.isValue(d.heads[e].clsColumn)&&n.addClass(d.heads[e].clsColumn),!1===b.bool(g[e].show)&&n.addClass("hidden"),b.bool(g[e].show)&&n.removeClass("hidden"),n.data("original",this),r[g[e]["index-view"]]=n,b.exec(h.onDrawCell,[n,t,e,d.heads[e],o],n[0]),u.fire("drawcell",{td:n,val:t,cellIndex:e,head:d.heads[e],items:o}),!0===h.cellWrapper&&(t=C("<div>").addClass("data-wrapper").addClass(h.clsCellWrapper).html(n.html()),n.html("").append(t))}),n=0;n<o.length;n++)r[n].appendTo(i),b.exec(h.onAppendCell,[r[n],i,n,u],r[n][0]),u.fire("appendcell",{td:r[n],tr:i,index:n});b.exec(h.onDrawRow,[i,d.view,d.heads,o],i[0]),u.fire("drawrow",{tr:i,view:d.view,heads:d.heads,items:o}),i.addClass(h.clsRow).addClass(l?h.clsEvenRow:h.clsOddRow).appendTo(p),b.exec(h.onAppendRow,[i,u],i[0]),u.fire("appendrow",{tr:i})}}else n=0,C.each(g,function(){this.show&&n++}),!0===h.check&&n++,!0===h.rownum&&n++,i=C("<tr>").addClass(h.clsBodyRow).appendTo(p),(s=C("<td>").attr("colspan",n).addClass("text-center").html(C("<span>").addClass(h.clsEmptyTableTitle).html(h.emptyTableTitle))).appendTo(i);this._info(1+f,1+m,c.length),this._paging(c.length),this.activity&&this.activity.hide(),b.exec(h.onDraw,[u],u[0]),u.fire("draw",u[0]),void 0!==e&&b.exec(e,[u],u[0])}else console.warn("Heads is not defined for table ID "+u.attr("id"))},_getItemContent:function(e){var t,n=this.options,i=e[this.sort.colIndex],s=this.heads[this.sort.colIndex].format,a=b.isNull(this.heads)||b.isNull(this.heads[this.sort.colIndex])||!b.isValue(this.heads[this.sort.colIndex].formatMask)?"%Y-%m-%d":this.heads[this.sort.colIndex].formatMask,o=this.heads&&this.heads[this.sort.colIndex]&&this.heads[this.sort.colIndex].thousandSeparator?this.heads[this.sort.colIndex].thousandSeparator:n.thousandSeparator,r=this.heads&&this.heads[this.sort.colIndex]&&this.heads[this.sort.colIndex].decimalSeparator?this.heads[this.sort.colIndex].decimalSeparator:n.decimalSeparator;if(t=(""+i).toLowerCase().replace(/[\n\r]+|[\s]{2,}/g," ").trim(),b.isValue(t)&&b.isValue(s))switch(-1!==["number","int","float","money"].indexOf(s)&&(t=b.parseNumber(t,o,r)),s){case"date":t=b.isValue(a)?t.toDate(a):new Date(t);break;case"number":t=Number(t);break;case"int":t=parseInt(t);break;case"float":t=parseFloat(t);break;case"money":t=b.parseMoney(t);break;case"card":t=b.parseCard(t);break;case"phone":t=b.parsePhone(t)}return t},addItem:function(e,t){if(!Array.isArray(e))return console.warn("Item is not an array and can't be added"),this;this.items.push(e),!1!==t&&this.draw()},addItems:function(e,t){if(!Array.isArray(e))return console.warn("Items is not an array and can't be added"),this;e.forEach(function(e){Array.isArray(e)&&this.items.push(e,!1)}),this.draw(),!1!==t&&this.draw()},updateItem:function(e,n,t){var i=this.items[this.index[e]],s=null;return b.isNull(i)?(console.warn("Item is undefined for update"),this):(isNaN(n)&&this.heads.forEach(function(e,t){e.name===n&&(s=t)}),b.isNull(s)?console.warn("Item is undefined for update. Field "+n+" not found in data structure"):(i[s]=t,this.items[this.index[e]]=i),this)},getItem:function(e){return this.items[this.index[e]]},deleteItem:function(e,t){var n,i=[],s=b.isFunc(t);for(n=0;n<this.items.length;n++)s?b.exec(t,[this.items[n][e]])&&i.push(n):this.items[n][e]===t&&i.push(n);return this.items=b.arrayDeleteByMultipleKeys(this.items,i),this},deleteItemByName:function(e,t){var n,i,s=[],a=b.isFunc(t);for(n=0;n<this.heads.length;n++)if(this.heads[n].name===e){i=n;break}for(n=0;n<this.items.length;n++)a?b.exec(t,[this.items[n][i]])&&s.push(n):this.items[n][i]===t&&s.push(n);return this.items=b.arrayDeleteByMultipleKeys(this.items,s),this},draw:function(){return this._draw(),this},sorting:function(e){var a=this,o=this.element,r=this.options;return b.isValue(e)&&(this.sort.dir=e),b.exec(r.onSortStart,[this.items],o[0]),o.fire("sortstart",this.items),this.items.sort(function(e,t){var n=a._getItemContent(e),i=a._getItemContent(t),s=0;return n<i&&(s="asc"===a.sort.dir?-1:1),i<n&&(s="asc"===a.sort.dir?1:-1),0!==s&&(b.exec(r.onSortItemSwitch,[e,t,s],o[0]),o.fire("sortitemswitch",{a:e,b:t,result:s})),s}),b.exec(r.onSortStop,[this.items],o[0]),o.fire("sortstop",this.items),this},search:function(e){return this.searchString=e.trim().toLowerCase(),this.currentPage=1,this._draw(),this},_rebuild:function(e){var t,n=this,i=this.element,s=!1;this._createIndex(),!0===e&&(this.view=this._createView()),this._createTableHeader(),this._createTableBody(),this._createTableFooter(),0<this.heads.length&&C.each(this.heads,function(e){!s&&-1<["asc","desc"].indexOf(this.sortDir)&&(s=!0,n.sort.colIndex=e,n.sort.dir=this.sortDir)}),s&&(t=i.find(".sortable-column"),this._resetSortClass(t),C(t.get(n.sort.colIndex)).addClass("sort-"+n.sort.dir),this.sorting()),n.currentPage=1,n._draw()},setHeads:function(e){return this.heads=e,this},setHeadItem:function(e,t){var n,i;for(n=0;n<this.heads.length;n++)if(this.heads[n].name===e){i=n;break}return this.heads[i]=t,this},setItems:function(e){return this.items=e,this},setData:function(e){var t=this.options;return this.items=[],this.heads=[],this.foots=[],Array.isArray(t.head)&&(this.heads=t.head),Array.isArray(t.body)&&(this.items=t.body),this._createItemsFromJSON(e),this._rebuild(!0),this},loadData:function(e,t){var n=this,i=this.element,s=this.options;b.isValue(t)||(t=!0),i.html(""),b.isValue(e)?(s.source=e,b.exec(s.onDataLoad,[s.source],i[0]),i.fire("dataload",{source:s.source}),n.activity.show(function(){C.json(s.source).then(function(e){n.activity.hide(),n.items=[],n.heads=[],n.foots=[],b.exec(s.onDataLoaded,[s.source,e],i[0]),i.fire("dataloaded",{source:s.source,data:e}),Array.isArray(s.head)&&(n.heads=s.head),Array.isArray(s.body)&&(n.items=s.body),n._createItemsFromJSON(e),n._rebuild(t)},function(e){n.activity.hide(),b.exec(s.onDataLoadError,[s.source,e],i[0]),i.fire("dataloaderror",{source:s.source,xhr:e})})})):this._rebuild(t)},reload:function(e){this.loadData(this.options.source,e)},clear:function(){return this.items=[],this.draw()},next:function(){if(0!==this.items.length){if(this.currentPage++,!(this.currentPage>this.pagesCount))return this._draw(),this;this.currentPage=this.pagesCount}},prev:function(){if(0!==this.items.length){if(this.currentPage--,0!==this.currentPage)return this._draw(),this;this.currentPage=1}},first:function(){if(0!==this.items.length)return this.currentPage=1,this._draw(),this},last:function(){if(0!==this.items.length)return this.currentPage=this.pagesCount,this._draw(),this},page:function(e){return e<=0&&(e=1),e>this.pagesCount&&(e=this.pagesCount),this.currentPage=e,this._draw(),this},addFilter:function(e,t){var n,i=null,s=b.isFunc(e);if(!1!==s){for(n=0;n<this.filters.length;n++)if(b.isNull(this.filters[n])){i=n,this.filters[n]=s;break}return b.isNull(i)&&(this.filters.push(s),i=this.filters.length-1),!0===t&&(this.currentPage=1,this.draw()),i}},removeFilter:function(e,t){return!(this.filters[e]=null)===t&&(this.currentPage=1,this.draw()),this},removeFilters:function(e){return this.filters=[],!0===e&&(this.currentPage=1,this.draw()),this},getItems:function(){return this.items},getHeads:function(){return this.heads},getView:function(){return this.view},getFilteredItems:function(){return 0<this.filteredItems.length?this.filteredItems:this.items},getSelectedItems:function(){var e=this.element,t=this.options,n=w.storage.getItem(t.checkStoreKey.replace("$1",e.attr("id"))),i=[];return b.isValue(n)?(C.each(this.items,function(){-1!==n.indexOf(""+this[t.checkColIndex])&&i.push(this)}),i):[]},getStoredKeys:function(){var e=this.element,t=this.options;return w.storage.getItem(t.checkStoreKey.replace("$1",e.attr("id")),[])},clearSelected:function(e){var t=this.element,n=this.options;w.storage.setItem(n.checkStoreKey.replace("$1",t.attr("id")),[]),t.find("table-service-check-all input").prop("checked",!1),!0===e&&this._draw()},getFilters:function(){return this.filters},getFiltersIndexes:function(){return this.filtersIndexes},openInspector:function(e){var t=this.inspector;e?t.show(0,function(){t.css({top:(C(window).height()-t.outerHeight(!0))/2+pageYOffset,left:(C(window).width()-t.outerWidth(!0))/2+pageXOffset}).data("open",!0)}):t.hide().data("open",!1)},closeInspector:function(){this.openInspector(!1)},toggleInspector:function(){this.openInspector(!this.inspector.data("open"))},resetView:function(){this.view=this._createView(),this._createTableHeader(),this._createTableFooter(),this._draw(),this._resetInspector(),this._saveTableView()},rebuildIndex:function(){this._createIndex()},getIndex:function(){return this.index},export:function(e,t,n,i){var s,a,o,r,l,c,d,u,h=this,p=this.options,f=document.createElement("table"),m=C("<thead>").appendTo(f),v=C("<tbody>").appendTo(f),g=[];if("function"==typeof y.tableToCSV){for(t=b.isValue(t)?t.toLowerCase():"all-filtered",n=b.isValue(n)?n:b.elementId("table")+"-export.csv",l=C("<tr>"),o=this.heads,a=0;a<o.length;a++)g[a]=null;for(C.each(o,function(e){!1!==b.bool(h.view[e].show)&&(c=C("<th>"),b.isValue(this.title)&&c.html(this.title),g[h.view[e]["index-view"]]=c)}),a=0;a<o.length;a++)b.isValue(g[a])&&g[a].appendTo(l);for(l.appendTo(m),u="checked"===t?(d=0,(r=this.getSelectedItems()).length-1):"view"===t?(r=this._filter(),d=-1===parseInt(p.rows)?0:p.rows*(this.currentPage-1),-1===parseInt(p.rows)?r.length-1:d+p.rows-1):"all"===t?(d=0,(r=this.items).length-1):(d=0,(r=this._filter()).length-1),s=d;s<=u;s++)if(b.isValue(r[s])){for(l=C("<tr>"),o=r[s],a=0;a<o.length;a++)g[a]=null;for(C.each(o,function(e){!1!==b.bool(h.view[e].show)&&(c=C("<td>").html(this),g[h.view[e]["index-view"]]=c)}),a=0;a<o.length;a++)b.isValue(g[a])&&g[a].appendTo(l);l.appendTo(v)}y.tableToCSV(f,n,i),f.remove()}},changeAttribute:function(e){var t=this,n=this.element,i=this.options;switch(e){case"data-check":i.check=b.bool(n.attr("data-check")),t._service(),t._createTableHeader(),t._draw();break;case"data-rownum":i.rownum=b.bool(n.attr("data-rownum")),t._service(),t._createTableHeader(),t._draw()}},destroy:function(){var e=this.element,t=e.closest(".table-component"),n=t.find("input"),i=t.find("select");if(n.data("input").destroy(),i.data("select").destroy(),C(window).off(w.events.resize,{ns:this.id}),e.off(w.events.click,".sortable-column"),e.off(w.events.click,".table-service-check input"),e.off(w.events.click,".table-service-check-all input"),n.off(w.events.inputchange),b.isValue(this.wrapperSearch)){var s=this.wrapperSearch.find("input");0<s.length&&s.off(w.events.inputchange)}return t.off(w.events.click,".pagination .page-link"),b.isValue(this.wrapperPagination)&&this.wrapperPagination.off(w.events.click,".pagination .page-link"),e.off(w.events.click,".js-table-crud-button"),this._removeInspectorEvents(),e}})}(Metro,m4q),function(t,h){"use strict";var p=t.utils,n={materialtabsDeferred:0,deep:!1,fixedTabs:!1,duration:300,appBar:!1,clsComponent:"",clsTabs:"",clsTab:"",clsTabActive:"",clsMarker:"",onBeforeTabOpen:t.noop_true,onTabOpen:t.noop,onTabsScroll:t.noop,onTabsCreate:t.noop};t.materialTabsSetup=function(e){n=h.extend({},n,e)},window.metroMaterialTabsSetup,t.materialTabsSetup(window.metroMaterialTabsSetup),t.Component("material-tabs",{init:function(e,t){return this._super(t,e,n,{marker:null,scroll:0,scrollDir:"left"}),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("tabs-create",{element:e})},_applyColor:function(e,t,n){e=h(e),p.isValue(t)&&(p.isColor(t)?e.css(n,t):e.addClass(t))},_createStructure:function(){var e=this.element,t=this.options,n=e.find("li"),i=e.find("li.active"),s=h("<div>").addClass("tabs-material-wrapper").addClass(t.clsComponent).insertBefore(e);!0===t.appBar&&s.addClass("app-bar-present"),"more"===t.appBar&&s.addClass("app-bar-present-more"),e.appendTo(s),e.addClass("tabs-material").addClass(t.clsTabs),n.addClass(t.clsTab),!0===t.deep&&e.addClass("deep"),!0===t.fixedTabs&&e.addClass("fixed-tabs"),this.marker=e.find(".tab-marker"),0===this.marker.length&&(this.marker=h("<span>").addClass("tab-marker").addClass(t.clsMarker).appendTo(e)),this.openTab(0===i.length?n[0]:i[0])},_createEvents:function(){var a=this,o=this.element,r=this.options;o.on(t.events.click,"li",function(e){var t=h(this),n=o.find("li.active"),i=t.index()>n.index(),s=t.children("a").attr("href");if(p.isValue(s)&&"#"===s[0]){if(t.hasClass("active"))return;if(t.hasClass("disabled"))return;if(!1===p.exec(r.onBeforeTabOpen,[t,s,i],this))return;a.openTab(t,i),e.preventDefault()}}),o.on(t.events.scroll,function(){var e=this.scroll;this.scrollDir=this.scroll<o[0].scrollLeft?"left":"right",this.scroll=o[0].scrollLeft,p.exec(r.onTabsScroll,[o[0].scrollLeft,e,this.scrollDir],o[0]),o.fire("tabsscroll",{scrollLeft:o[0].scrollLeft,oldScroll:e,scrollDir:a.scrollDir})})},openTab:function(e,t){var n,i,s,a,o,r,l,c=this.element,d=this.options,u=c.find("li");e=h(e),h.each(u,function(){var e=h(this).find("a").attr("href");p.isValue(e)&&"#"===e[0]&&1<e.length&&h(e).hide()}),i=c.width(),r=c.scrollLeft(),n=(o=e.position().left)+(s=e.width()),u.removeClass("active").removeClass(d.clsTabActive),e.addClass("active").addClass(d.clsTabActive),l=i+r<n+52?r+104:o<r?o-104:r,c.animate({draw:{scrollLeft:l},dur:d.duration}),this.marker.animate({draw:{left:o,width:s},dur:d.duration}),a=e.find("a").attr("href"),p.isValue(a)&&"#"===a[0]&&1<a.length&&h(a).show(),this._fireEvent("tab-open",{tab:e[0],target:a,tab_next:t})},open:function(e){var t=this.element,n=t.find("li"),i=t.find("li.active"),s=n.eq(e-1),a=n.index(s)>n.index(i);this.openTab(s,a)},changeAttribute:function(){},destroy:function(){var e=this.element;return e.off(t.events.click,"li"),e.off(t.events.scroll),e}})}(Metro,m4q),function(n,l){"use strict";var c=n.utils,d=n.colors,i={tabsDeferred:0,expand:!1,expandPoint:null,tabsPosition:"top",tabsType:"default",clsTabs:"",clsTabsList:"",clsTabsListItem:"",clsTabsListItemActive:"",onTab:n.noop,onBeforeTab:n.noop_true,onTabsCreate:n.noop};n.tabsSetup=function(e){i=l.extend({},i,e)},window.metroTabsSetup,n.tabsSetup(window.metroTabsSetup),n.Component("tabs",{init:function(e,t){return this._super(t,e,i,{_targets:[],id:c.elementId("tabs")}),this},_create:function(){var e=this.element,t=0<e.find(".active").length?l(e.find(".active")[0]):void 0;this._createStructure(),this._createEvents(),this._open(t),this._fireEvent("tabs-create",{element:e})},_createStructure:function(){var e,t,n=this.element,i=this.options,s=n.parent(),a=s.hasClass("tabs"),o=a?s:l("<div>").addClass("tabs tabs-wrapper");if(o.addClass(i.tabsPosition.replace(["-","_","+"]," ")),n.addClass("tabs-list"),"default"!==i.tabsType&&n.addClass("tabs-"+i.tabsType),a||(o.insertBefore(n),n.appendTo(o)),n.data("expanded",!1),e=l("<div>").addClass("expand-title"),o.prepend(e),0===(t=o.find(".hamburger")).length){t=l("<button>").attr("type","button").addClass("hamburger menu-down").appendTo(o);for(var r=0;r<3;r++)l("<span>").addClass("line").appendTo(t);!0===d.isLight(c.computedRgbToHex(c.getStyleOne(o,"background-color")))&&t.addClass("dark")}o.addClass(i.clsTabs),n.addClass(i.clsTabsList),n.children("li").addClass(i.clsTabsListItem),!0!==i.expand||i.tabsPosition.contains("vertical")?c.isValue(i.expandPoint)&&c.mediaExist(i.expandPoint)&&!i.tabsPosition.contains("vertical")&&o.addClass("tabs-expand"):o.addClass("tabs-expand"),i.tabsPosition.contains("vertical")&&o.addClass("tabs-expand")},_createEvents:function(){var s=this,a=this.element,o=this.options,r=a.parent();l(window).on(n.events.resize,function(){o.tabsPosition.contains("vertical")||(!0!==o.expand||o.tabsPosition.contains("vertical")?c.isValue(o.expandPoint)&&c.mediaExist(o.expandPoint)&&!o.tabsPosition.contains("vertical")?r.hasClass("tabs-expand")||r.addClass("tabs-expand"):r.hasClass("tabs-expand")&&r.removeClass("tabs-expand"):r.addClass("tabs-expand"))},{ns:this.id}),r.on(n.events.click,".hamburger, .expand-title",function(){!1===a.data("expanded")?(a.addClass("expand"),a.data("expanded",!0),r.find(".hamburger").addClass("active")):(a.removeClass("expand"),a.data("expanded",!1),r.find(".hamburger").removeClass("active"))}),a.on(n.events.click,"a",function(e){var t=l(this),n=t.attr("href").trim(),i=t.parent("li");if(i.hasClass("active")&&e.preventDefault(),!0===a.data("expanded")&&(a.removeClass("expand"),a.data("expanded",!1),r.find(".hamburger").removeClass("active")),!0!==c.exec(o.onBeforeTab,[i,a],i[0]))return!1;c.isValue(n)&&"#"===n[0]&&(s._open(i),e.preventDefault())})},_collectTargets:function(){var t=this,e=this.element.find("li");this._targets=[],l.each(e,function(){var e=l(this).find("a").attr("href").trim();1<e.length&&"#"===e[0]&&t._targets.push(e)})},_open:function(e){var t=this.element,n=this.options,i=t.find("li"),s=t.siblings(".expand-title");if(0!==i.length){this._collectTargets(),void 0===e&&(e=l(i[0]));var a=e.find("a").attr("href");void 0!==a&&(i.removeClass("active").removeClass(n.clsTabsListItemActive),e.parent().hasClass("d-menu")?e.parent().parent().addClass("active"):e.addClass("active"),l.each(this._targets,function(){var e=l(this);0<e.length&&e.hide()}),"#"!==a&&"#"===a[0]&&l(a).show(),s.html(e.find("a").html()),e.addClass(n.clsTabsListItemActive),c.exec(n.onTab,[e[0]],t[0]),t.fire("tab",{tab:e[0]}))}},next:function(){var e;0<(e=this.element.find("li.active").next("li")).length&&this._open(e)},prev:function(){var e;0<(e=this.element.find("li.active").prev("li")).length&&this._open(e)},open:function(e){var t=this.element.find("li");c.isValue(e)||(e=1),c.isInt(e)?c.isValue(t[e-1])&&this._open(l(t[e-1])):this._open(l(e))},changeAttribute:function(){},destroy:function(){var e=this.element,t=e.parent();return l(window).off(n.events.resize,{ns:this.id}),t.off(n.events.click,".hamburger, .expand-title"),e.off(n.events.click,"a"),e}})}(Metro,m4q),function(r,p){"use strict";var f=r.colors,m=r.utils,n={size:"normal",taginputDeferred:0,static:!1,clearButton:!0,clearButtonIcon:"<span class='default-icon-cross'></span>",randomColor:!1,maxTags:0,tagSeparator:",",tagTrigger:"Enter, Space, Comma",backspace:!0,clsComponent:"",clsInput:"",clsClearButton:"",clsTag:"",clsTagTitle:"",clsTagRemover:"",onBeforeTagAdd:r.noop_true,onTagAdd:r.noop,onBeforeTagRemove:r.noop_true,onTagRemove:r.noop,onTag:r.noop,onClear:r.noop,onTagTrigger:r.noop,onTagInputCreate:r.noop};r.tagInputSetup=function(e){n=p.extend({},n,e)},window.metroTagInputSetup,r.tagInputSetup(window.metroTagInputSetup),r.Component("tag-input",{init:function(e,t){return this._super(t,e,n,{values:[],triggers:[]}),this},_create:function(){this.triggers=(""+this.options.tagTrigger).toArray(","),(this.triggers.contains("Space")||this.triggers.contains("Spacebar"))&&(this.triggers.push(" "),this.triggers.push("Spacebar")),this.triggers.contains("Comma")&&this.triggers.push(","),this._createStructure(),this._createEvents(),this._fireEvent("tag-input-create",{element:this.element})},_createStructure:function(){var e,t=this,n=this.element,i=this.options,s=n.val().trim();e=p("<div>").addClass("tag-input "+n[0].className).addClass(i.clsComponent).insertBefore(n),n.appendTo(e),e.addClass("input-"+i.size),n[0].className="",n.addClass("original-input"),p("<input type='text'>").addClass("input-wrapper").addClass(i.clsInput).attr("size",1).appendTo(e),!1===i.clearButton||n[0].readOnly||(e.addClass("padding-for-clear"),p("<button>").addClass("button input-clear-button").attr("tabindex",-1).attr("type","button").html(i.clearButtonIcon).appendTo(e)),m.isValue(s)&&p.each(s.toArray(i.tagSeparator),function(){t._addTag(this)}),n.is(":disabled")?this.disable():this.enable(),!0!==i.static&&void 0===n.attr("readonly")||e.addClass("static-mode")},_createEvents:function(){var i=this,s=this.element,a=this.options,e=s.closest(".tag-input"),o=e.find(".input-wrapper");o.on(r.events.focus,function(){e.addClass("focused")}),o.on(r.events.blur,function(){e.removeClass("focused")}),o.on(r.events.inputchange,function(){o.attr("size",Math.ceil(o.val().length/2)+2)}),o.on(r.events.keydown,function(e){var t=o.val().trim(),n=e.key;"Enter"===n&&e.preventDefault(),!0!==a.backspace||"Backspace"!==n||0!==t.length?""!==t&&i.triggers.contains(n)&&(m.exec(a.onTagTrigger,[n],s[0]),s.fire("tagtrigger",{key:n}),o.val(""),i._addTag(t),o.attr("size",1)):0<i.values.length&&(i.values.splice(-1,1),s.siblings(".tag").last().remove(),s.val(i.values.join(a.tagSeparator)))}),o.on(r.events.keyup,function(e){var t=o.val(),n=e.key;i.triggers.contains(n)&&t[t.length-1]===n&&o.val(t.slice(0,-1))}),e.on(r.events.click,".tag .remover",function(){var e=p(this).closest(".tag");i._delTag(e)}),e.on(r.events.click,function(){o.focus()}),e.on(r.events.click,".input-clear-button",function(){var e=s.val();i.clear(),m.exec(a.onClear,[e],s[0]),s.fire("clear",{val:e})})},_addTag:function(e){var t,n,i,s,a=this.element,o=this.options,r=a.closest(".tag-input"),l=r.find(".input-wrapper");if(r.hasClass("input-large")?s="large":r.hasClass("input-small")&&(s="small"),!(0<o.maxTags&&this.values.length===o.maxTags)&&""!==(""+e).trim()&&m.exec(o.onBeforeTagAdd,[e,this.values],a[0])){if((t=p("<span>").addClass("tag").addClass(s).addClass(o.clsTag).insertBefore(l)).data("value",e),(o.static||r.hasClass("static-mode")||a.readonly||a.disabled||r.hasClass("disabled"))&&t.addClass("static"),n=p("<span>").addClass("title").addClass(o.clsTagTitle).html(e),i=p("<span>").addClass("remover").addClass(o.clsTagRemover).html("&times;"),n.appendTo(t),i.appendTo(t),!0===o.randomColor){var c,d,u,h=f.colors(f.PALETTES.ALL);c=h[p.random(0,h.length-1)],u=f.darken(c,15),d=f.isDark(c)?"#ffffff":"#000000",t.css({backgroundColor:c,color:d}),i.css({backgroundColor:u,color:d})}this.values.push(e),a.val(this.values.join(o.tagSeparator)),m.exec(o.onTagAdd,[t[0],e,this.values],a[0]),a.fire("tagadd",{tag:t[0],val:e,values:this.values}),m.exec(o.onTag,[t[0],e,this.values],a[0]),a.fire("tag",{tag:t[0],val:e,values:this.values})}},_delTag:function(e){var t=this.element,n=this.options,i=e.data("value");m.exec(n.onBeforeTagRemove,[e,i,this.values],t[0])&&(m.arrayDelete(this.values,i),t.val(this.values.join(n.tagSeparator)),m.exec(n.onTagRemove,[e[0],i,this.values],t[0]),t.fire("tagremove",{tag:e[0],val:i,values:this.values}),m.exec(n.onTag,[e[0],i,this.values],t[0]),t.fire("tag",{tag:e[0],val:i,values:this.values}),e.remove())},tags:function(){return this.values},val:function(e){var t=this,n=this.options;if(!m.isValue(e))return this.tags();this.values=[],m.isValue(e)&&p.each((""+e).toArray(n.tagSeparator),function(){t._addTag(this)})},clear:function(){var e=this.element,t=e.closest(".tag-input");this.values=[],e.val("").trigger("change"),t.find(".tag").remove()},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},toggleStatic:function(e){var t=this.element.closest(".tag-input");(m.isValue(e)?m.bool(e):!t.hasClass("static-mode"))?t.addClass("static-mode"):t.removeClass("static-mode")},changeAttribute:function(e){var t,n=this,i=this.element,s=this.options;switch(e){case"value":t=i.attr("value").trim(),n.clear(),m.isValue(t)&&n.val(t.toArray(s.tagSeparator));break;case"disabled":this.toggleState();break;case"static":this.toggleStatic()}},destroy:function(){var e=this.element,t=e.closest(".tag-input"),n=t.find(".input-wrapper");return n.off(r.events.focus),n.off(r.events.blur),n.off(r.events.keydown),t.off(r.events.click,".tag .remover"),t.off(r.events.click),e}})}(Metro,m4q),function(e,u){"use strict";var h=e.utils;e.template=function(e,t,n){var i,s,a,o="<%(.+?)%>",r=/(^( )?(var|if|for|else|switch|case|break|{|}|;))(.*)?/g,l="with(obj) { var r=[];\n",c=0,d=function(e,t){return l+=t?e.match(r)?e+"\n":"r.push("+e+");\n":""!==e?'r.push("'+e.replace(/"/g,'\\"')+'");\n':"",d};for(h.isValue(n)&&(u.hasProp(n,"beginToken")&&(o=o.replace("<%",n.beginToken)),u.hasProp(n,"endToken")&&(o=o.replace("%>",n.endToken))),a=(i=new RegExp(o,"g")).exec(e);a;)d(e.slice(c,a.index))(a[1],!0),c=a.index+a[0].length,a=i.exec(e);d(e.substr(c,e.length-c)),l=(l+'return r.join(""); }').replace(/[\r\t\n]/g," ");try{s=new Function("obj",l).apply(t,[t])}catch(e){console.error("'"+e.message+"'"," in \n\nCode:\n",l,"\n")}return s}}(Metro,m4q),function(e,t){"use strict";var n=e.utils,i=e.template,s={templateData:null,onTemplateCompile:e.noop,onTemplateCreate:e.noop};e.templateSetup=function(e){s=t.extend({},s,e)},window.metroTemplateSetup,e.templateSetup(window.metroTemplateSetup),e.Component("template",{init:function(e,t){return this._super(t,e,s,{template:null,data:{}}),this},_compile:function(){var e,t,n=this.element;e=this.template.replace(/(&lt;%)/gm,"<%").replace(/(%&gt;)/gm,"%>").replace(/(&lt;)/gm,"<").replace(/(&gt;)/gm,">"),t=i(e,this.data),n.html(t),this._fireEvent("template-compile",{template:e,compiled:t,element:n})},_create:function(){var e=this.element,t=this.options;this.template=e.html(),this.data=n.isObject(t.templateData)||{},this._compile(),this._fireEvent("template-create",{element:e})},buildWith:function(e){var t=n.isObject(e);t&&(this.data=t,this._compile())},changeAttribute:function(e,t){"data-template-data"===e&&(this.options.templateData=t,this.data=n.isObject(t)||{},this._compile())},destroy:function(){return this.element}})}(Metro,m4q),function(o,d){"use strict";var u=o.utils,n={textareaDeferred:0,charsCounter:null,charsCounterTemplate:"$1",defaultValue:"",prepend:"",append:"",copyInlineStyles:!1,clearButton:!0,clearButtonIcon:"<span class='default-icon-cross'></span>",autoSize:!0,clsPrepend:"",clsAppend:"",clsComponent:"",clsTextarea:"",onChange:o.noop,onTextareaCreate:o.noop};o.textareaSetup=function(e){n=d.extend({},n,e)},window.metroTextareaSetup,o.textareaSetup(window.metroTextareaSetup),o.Component("textarea",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e=this.element;this._createStructure(),this._createEvents(),this._fireEvent("textarea-create",{element:e})},_createStructure:function(){var e,t=this,n=this.element,i=this.elem,s=this.options,a=d("<div>").addClass("textarea "+n[0].className),o=d("<textarea>").addClass("fake-textarea");a.insertBefore(n),n.appendTo(a),o.appendTo(a),!1===s.clearButton||n[0].readOnly||(e=d("<button>").addClass("button input-clear-button").attr("tabindex",-1).attr("type","button").html(s.clearButtonIcon)).appendTo(a),"rtl"===n.attr("dir")&&a.addClass("rtl").attr("dir","rtl"),""!==s.prepend&&d("<div>").html(s.prepend).addClass("prepend").addClass(s.clsPrepend).appendTo(a);if(""!==s.append){var r=d("<div>").html(s.append);r.addClass("append").addClass(s.clsAppend).appendTo(a),e.css({right:r.outerWidth()+4})}if(!(i.className="")===s.copyInlineStyles)for(var l=0,c=i.style.length;l<c;l++)a.css(i.style[l],n.css(i.style[l]));u.isValue(s.defaultValue)&&""===n.val().trim()&&n.val(s.defaultValue),a.addClass(s.clsComponent),n.addClass(s.clsTextarea),n.is(":disabled")?this.disable():this.enable(),o.val(n.val()),!0===s.autoSize&&(a.addClass("autosize no-scroll-vertical"),setTimeout(function(){t.resize()},100))},_createEvents:function(){var e=this,t=this.element,n=this.options,i=t.closest(".textarea"),s=i.find(".fake-textarea"),a=d(n.charsCounter);i.on(o.events.click,".input-clear-button",function(){t.val(u.isValue(n.defaultValue)?n.defaultValue:"").trigger("change").trigger("keyup").focus()}),n.autoSize&&t.on(o.events.inputchange+" "+o.events.keyup,function(){s.val(this.value),e.resize()}),t.on(o.events.blur,function(){i.removeClass("focused")}),t.on(o.events.focus,function(){i.addClass("focused")}),t.on(o.events.keyup,function(){u.isValue(n.charsCounter)&&0<a.length&&("INPUT"===a[0].tagName?a.val(e.length()):a.html(n.charsCounterTemplate.replace("$1",e.length()))),u.exec(n.onChange,[t.val(),e.length()],t[0]),t.fire("change",{val:t.val(),length:e.length()})})},resize:function(){var e=this.element,t=e.closest(".textarea").find(".fake-textarea");t[0].style.cssText="height:auto;",t[0].style.cssText="height:"+t[0].scrollHeight+"px",e[0].style.cssText="height:"+t[0].scrollHeight+"px"},clear:function(){this.element.val("").trigger("change").trigger("keyup").focus()},toDefault:function(){this.element.val(u.isValue(this.options.defaultValue)?this.options.defaultValue:"").trigger("change").trigger("keyup").focus()},length:function(){return this.elem.value.split("").length},disable:function(){this.element.data("disabled",!0),this.element.parent().addClass("disabled")},enable:function(){this.element.data("disabled",!1),this.element.parent().removeClass("disabled")},toggleState:function(){this.elem.disabled?this.disable():this.enable()},changeAttribute:function(e){switch(e){case"disabled":this.toggleState()}},destroy:function(){var e=this.element,t=this.options;return e.closest(".textarea").off(o.events.click,".input-clear-button"),t.autoSize&&e.off(o.events.inputchange+" "+o.events.keyup),e.off(o.events.blur),e.off(o.events.focus),e.off(o.events.keyup),e}})}(Metro,m4q),function(s,u){"use strict";var h=s.utils,p=["slide-up","slide-down","slide-left","slide-right","fade","zoom","swirl","switch"],n={tileDeferred:0,size:"medium",cover:"",coverPosition:"center",effect:"",effectInterval:3e3,effectDuration:500,target:null,canTransform:!0,onClick:s.noop,onTileCreate:s.noop};s.tileSetup=function(e){n=u.extend({},n,e)},window.metroTileSetup,s.tileSetup(window.metroTileSetup),s.Component("tile",{init:function(e,t){return this._super(t,e,n,{effectInterval:!1,images:[],slides:[],currentSlide:-1,unload:!1}),this},_create:function(){var e=this.element;this._createTile(),this._createEvents(),this._fireEvent("tile-create",{element:e})},_createTile:function(){function s(e,t,n){u.setTimeout(function(){e.fadeOut(500,function(){e.css("background-image","url("+t+")"),e.fadeIn()})},300*n)}var a=this,o=this.element,n=this.options,e=o.find(".slide"),t=o.find(".slide-front, .slide-back");if(o.addClass("tile-"+n.size),-1<n.effect.indexOf("hover-")&&(o.addClass("effect-"+n.effect),u.each(t,function(){var e=u(this);void 0!==e.data("cover")&&a._setCover(e,e.data("cover"),e.data("cover-position"))})),p.includes(n.effect)&&1<e.length&&(u.each(e,function(e){var t=u(this);a.slides.push(this),void 0!==t.data("cover")&&a._setCover(t,t.data("cover"),t.data("cover-position")),0<e&&(-1<["slide-up","slide-down"].indexOf(n.effect)&&t.css("top","100%"),-1<["slide-left","slide-right"].indexOf(n.effect)&&t.css("left","100%"),-1<["fade","zoom","swirl","switch"].indexOf(n.effect)&&t.css("opacity",0))}),this.currentSlide=0,this._runEffects()),""!==n.cover&&this._setCover(o,n.cover),"image-set"===n.effect){o.addClass("image-set"),u.each(o.children("img"),function(){a.images.push(this),u(this).remove()});for(var i=this.images.slice(),r=0;r<5;r++){var l=u.random(0,i.length-1),c=u("<div>").addClass("img -js-img-"+r).css("background-image","url("+i[l].src+")");o.prepend(c),i.splice(l,1)}var d=[0,1,4,3,2];u.setInterval(function(){var e=a.images.slice(),t=h.randomColor();o.css("background-color",t);for(var n=0;n<d.length;n++){var i=u.random(0,e.length-1);s(o.find(".-js-img-"+d[n]),e[i].src,n),e.splice(i,1)}d=d.reverse()},5e3)}},_runEffects:function(){var n=this,i=this.options;!1===this.effectInterval&&(this.effectInterval=u.setInterval(function(){var e,t;e=u(n.slides[n.currentSlide]),n.currentSlide++,n.currentSlide===n.slides.length&&(n.currentSlide=0),t=n.slides[n.currentSlide],p.includes(i.effect)&&s.animations[i.effect.camelCase()](u(e),u(t),{duration:i.effectDuration})},i.effectInterval))},_stopEffects:function(){u.clearInterval(this.effectInterval),this.effectInterval=!1},_setCover:function(e,t,n){h.isValue(n)||(n=this.options.coverPosition),e.css({backgroundImage:"url("+t+")",backgroundSize:"cover",backgroundRepeat:"no-repeat",backgroundPosition:n})},_createEvents:function(){var r=this.element,l=this.options;r.on(s.events.startAll,function(e){var t,n=u(this),i=r.width(),s=r.height(),a=h.pageXY(e).x-n.offset().left,o=h.pageXY(e).y-n.offset().top;!1===h.isRightMouse(e)&&(t=a<1*i/3&&(o<1*s/2||1*s/2<o)?"left":2*i/3<a&&(o<1*s/2||1*s/2<o)?"right":1*i/3<a&&a<2*i/3&&s/2<o?"bottom":"top",!0===l.canTransform&&n.addClass("transform-"+t),null!==l.target&&setTimeout(function(){document.location.href=l.target},100),h.exec(l.onClick,[t],r[0]),r.fire("click",{side:t}))}),r.on([s.events.stopAll,s.events.leave].join(" "),function(){u(this).removeClass("transform-left").removeClass("transform-right").removeClass("transform-top").removeClass("transform-bottom")})},changeAttribute:function(){},destroy:function(){var e=this.element;return e.off(s.events.startAll),e.off([s.events.stopAll,s.events.leave].join(" ")),e}})}(Metro,m4q),function(i,f){"use strict";var g=i.utils,n={timepickerDeferred:0,hoursStep:1,minutesStep:1,secondsStep:1,value:null,locale:METRO_LOCALE,distance:3,hours:!0,minutes:!0,seconds:!0,showLabels:!0,scrollSpeed:4,copyInlineStyles:!1,clsPicker:"",clsPart:"",clsHours:"",clsMinutes:"",clsSeconds:"",okButtonIcon:"<span class='default-icon-check'></span>",cancelButtonIcon:"<span class='default-icon-cross'></span>",onSet:i.noop,onOpen:i.noop,onClose:i.noop,onScroll:i.noop,onTimePickerCreate:i.noop};i.timePickerSetup=function(e){n=f.extend({},n,e)},window.metroTimePickerSetup,i.timePickerSetup(window.metroTimePickerSetup),i.Component("time-picker",{init:function(e,t){return this._super(t,e,n,{picker:null,isOpen:!1,value:[],locale:i.locales[METRO_LOCALE].calendar,listTimer:{hours:null,minutes:null,seconds:null}}),this},_create:function(){var e,t=this.element,n=this.options;for(n.distance<1&&(n.distance=1),n.hoursStep<1&&(n.hoursStep=1),23<n.hoursStep&&(n.hoursStep=23),n.minutesStep<1&&(n.minutesStep=1),59<n.minutesStep&&(n.minutesStep=59),n.secondsStep<1&&(n.secondsStep=1),59<n.secondsStep&&(n.secondsStep=59),""!==t.val()||g.isValue(n.value)||(n.value=(new Date).format("%H:%M:%S")),this.value=(""!==t.val()?t.val():""+n.value).toArray(":"),e=0;e<3;e++)void 0===this.value[e]||null===this.value[e]?this.value[e]=0:this.value[e]=parseInt(this.value[e]);this._normalizeValue(),void 0===i.locales[n.locale]&&(n.locale=METRO_LOCALE),this.locale=i.locales[n.locale].calendar,this._createStructure(),this._createEvents(),this._set(),this._fireEvent("time-picker-create",{element:t})},_normalizeValue:function(){var e=this.options;1<e.hoursStep&&(this.value[0]=g.nearest(this.value[0],e.hoursStep,!0)),1<e.minutesStep&&(this.value[1]=g.nearest(this.value[1],e.minutesStep,!0)),1<e.minutesStep&&(this.value[2]=g.nearest(this.value[2],e.secondsStep,!0))},_createStructure:function(){var e,t,n,i,s,a,o,r,l,c=this.element,d=this.options,u=c.prev(),h=c.parent(),p=g.elementId("time-picker");if(e=f("<div>").attr("id",p).addClass("wheel-picker time-picker "+c[0].className).addClass(d.clsPicker),0===u.length?h.prepend(e):e.insertAfter(u),c.attr("readonly",!0).appendTo(e),a=f("<div>").addClass("time-wrapper").appendTo(e),!0===d.hours&&(t=f("<div>").attr("data-title",this.locale.time.hours).addClass("hours").addClass(d.clsPart).addClass(d.clsHours).appendTo(a)),!0===d.minutes&&(n=f("<div>").attr("data-title",this.locale.time.minutes).addClass("minutes").addClass(d.clsPart).addClass(d.clsMinutes).appendTo(a)),!0===d.seconds&&(i=f("<div>").attr("data-title",this.locale.time.seconds).addClass("seconds").addClass(d.clsPart).addClass(d.clsSeconds).appendTo(a)),o=f("<div>").addClass("select-wrapper").appendTo(e),r=f("<div>").addClass("select-block").appendTo(o),!0===d.hours){for(t=f("<ul>").addClass("sel-hours").appendTo(r),s=0;s<d.distance;s++)f("<li>").html("&nbsp;").data("value",-1).appendTo(t);for(s=0;s<24;s+=d.hoursStep)f("<li>").addClass("js-hours-"+s).html(s<10?"0"+s:s).data("value",s).appendTo(t);for(s=0;s<d.distance;s++)f("<li>").html("&nbsp;").data("value",-1).appendTo(t)}if(!0===d.minutes){for(n=f("<ul>").addClass("sel-minutes").appendTo(r),s=0;s<d.distance;s++)f("<li>").html("&nbsp;").data("value",-1).appendTo(n);for(s=0;s<60;s+=d.minutesStep)f("<li>").addClass("js-minutes-"+s).html(s<10?"0"+s:s).data("value",s).appendTo(n);for(s=0;s<d.distance;s++)f("<li>").html("&nbsp;").data("value",-1).appendTo(n)}if(!0===d.seconds){for(i=f("<ul>").addClass("sel-seconds").appendTo(r),s=0;s<d.distance;s++)f("<li>").html("&nbsp;").data("value",-1).appendTo(i);for(s=0;s<60;s+=d.secondsStep)f("<li>").addClass("js-seconds-"+s).html(s<10?"0"+s:s).data("value",s).appendTo(i);for(s=0;s<d.distance;s++)f("<li>").html("&nbsp;").data("value",-1).appendTo(i)}if(r.height(40*(2*d.distance+1)),l=f("<div>").addClass("action-block").appendTo(o),f("<button>").attr("type","button").addClass("button action-ok").html(d.okButtonIcon).appendTo(l),f("<button>").attr("type","button").addClass("button action-cancel").html(d.cancelButtonIcon).appendTo(l),!(c[0].className="")===d.copyInlineStyles)for(s=0;s<c[0].style.length;s++)e.css(c[0].style[s],c.css(c[0].style[s]));!0===d.showLabels&&e.addClass("show-labels"),this.picker=e},_createEvents:function(){var r=this,a=this.options,l=this.picker;l.on(i.events.start,".select-block ul",function(e){if(!e.changedTouches){var t=this,n=g.pageXY(e).y;f(document).on(i.events.move,function(e){t.scrollTop-=a.scrollSpeed*(n>g.pageXY(e).y?-1:1),n=g.pageXY(e).y},{ns:l.attr("id")}),f(document).on(i.events.stop,function(){f(document).off(i.events.move,{ns:l.attr("id")}),f(document).off(i.events.stop,{ns:l.attr("id")})},{ns:l.attr("id")})}}),l.on(i.events.click,function(e){!1===r.isOpen&&r.open(),e.stopPropagation()}),l.on(i.events.click,".action-ok",function(e){var t,n,i,s=l.find(".sel-hours li.active"),a=l.find(".sel-minutes li.active"),o=l.find(".sel-seconds li.active");t=0===s.length?0:s.data("value"),n=0===a.length?0:a.data("value"),i=0===o.length?0:o.data("value"),r.value=[t,n,i],r._normalizeValue(),r._set(),r.close(),e.stopPropagation()}),l.on(i.events.click,".action-cancel",function(e){r.close(),e.stopPropagation()});f.each(["hours","minutes","seconds"],function(){var i=this,s=l.find(".sel-"+i);s.on("scroll",function(){r.isOpen&&(r.listTimer[i]&&(clearTimeout(r.listTimer[i]),r.listTimer[i]=null),r.listTimer[i]||(r.listTimer[i]=setTimeout(function(){var e,t,n;r.listTimer[i]=null,e=Math.round(Math.ceil(s.scrollTop())/40),n=(t=s.find(".js-"+i+"-"+e)).position().top-40*a.distance,s.find(".active").removeClass("active"),s[0].scrollTop=n,t.addClass("active"),g.exec(a.onScroll,[t,s,l],s[0])},150)))})})},_set:function(){var e=this.element,t=this.options,n=this.picker,i="00",s="00",a="00";!0===t.hours&&((i=parseInt(this.value[0]))<10&&(i="0"+i),n.find(".hours").html(i)),!0===t.minutes&&((s=parseInt(this.value[1]))<10&&(s="0"+s),n.find(".minutes").html(s)),!0===t.seconds&&((a=parseInt(this.value[2]))<10&&(a="0"+a),n.find(".seconds").html(a)),e.val([i,s,a].join(":")).trigger("change"),g.exec(t.onSet,[this.value,e.val()],e[0]),e.fire("set",{val:this.value,elementVal:e.val()})},open:function(){var e,t,n,i,s,a,o,r,l,c,d,u=this.element,h=this.options,p=this.picker,f=p.find("li"),m=p.find(".select-wrapper");m.parent().removeClass("for-top for-bottom"),m.show(0),f.removeClass("active"),o=g.inViewport(m[0]),r=g.rect(m[0]),!o&&0<r.top&&m.parent().addClass("for-bottom"),!o&&r.top<0&&m.parent().addClass("for-top");function v(e,t){e.scrollTop(0).animate({draw:{scrollTop:t.position().top-40*h.distance+e.scrollTop()},dur:100})}!0===h.hours&&(e=parseInt(this.value[0]),l=(i=p.find(".sel-hours")).find("li.js-hours-"+e).addClass("active"),v(i,l)),!0===h.minutes&&(t=parseInt(this.value[1]),c=(s=p.find(".sel-minutes")).find("li.js-minutes-"+t).addClass("active"),v(s,c)),!0===h.seconds&&(n=parseInt(this.value[2]),d=(a=p.find(".sel-seconds")).find("li.js-seconds-"+n).addClass("active"),v(a,d)),this.isOpen=!0,g.exec(h.onOpen,[this.value],u[0]),u.fire("open",{val:this.value})},close:function(){var e=this.picker,t=this.options,n=this.element;e.find(".select-wrapper").hide(0),this.isOpen=!1,g.exec(t.onClose,[this.value],n[0]),n.fire("close",{val:this.value})},_convert:function(e){return Array.isArray(e)?e:"function"==typeof e.getMonth?[e.getHours(),e.getMinutes(),e.getSeconds()]:g.isObject(e)?[e.h,e.m,e.s]:e.toArray(":")},val:function(e){if(void 0===e)return this.element.val();this.value=this._convert(e),this._normalizeValue(),this._set()},time:function(e){if(void 0===e)return{h:this.value[0],m:this.value[1],s:this.value[2]};this.value=this._convert(e),this._normalizeValue(),this._set()},date:function(e){if(void 0===e||"function"!=typeof e.getMonth){var t=new Date;return t.setHours(this.value[0]),t.setMinutes(this.value[1]),t.setSeconds(this.value[2]),t.setMilliseconds(0),t}this.value=this._convert(e),this._normalizeValue(),this._set()},changeAttribute:function(e){var t=this,n=this.element;"data-value"===e&&t.val(n.attr("data-value"))},destroy:function(){var e=this.element,t=this.picker;return f.each(["hours","minutes","seconds"],function(){t.find(".sel-"+this).off("scroll")}),t.off(i.events.start,".select-block ul"),t.off(i.events.click),t.off(i.events.click,".action-ok"),t.off(i.events.click,".action-cancel"),e}}),f(document).on(i.events.click,function(){f.each(f(".time-picker"),function(){f(this).find("input").each(function(){i.getPlugin(this,"timepicker").close()})})})}(Metro,m4q),function(e,c){"use strict";var n=e.utils,d={callback:e.noop,timeout:METRO_TIMEOUT,distance:20,showTop:!1,clsToast:""};e.toastSetup=function(e){d=c.extend({},d,e)},window.metroToastSetup,e.toastSetup(window.metroToastSetup);var u={create:function(e,t){var n,i,s,a,o,r,l=Array.from(arguments);c.isPlainObject(t)||(t=l[4],o=l[1],a=l[2],r=l[3]),n=c.extend({},d,t),s=(i=c("<div>").addClass("toast").html(e).appendTo(c("body"))).outerWidth(),i.hide(),a=a||n.timeout,o=o||n.callback,r=r||n.clsToast,!0===n.showTop?i.addClass("show-top").css({top:n.distance}):i.css({bottom:n.distance}),i.css({left:"50%","margin-left":-s/2}).addClass(n.clsToast).addClass(r).fadeIn(METRO_ANIMATION_DURATION,function(){setTimeout(function(){u.remove(i,o)},a)})},remove:function(e,t){e&&e.fadeOut(METRO_ANIMATION_DURATION,function(){e.remove(),n.exec(t,null,e[0])})}};e.toast=u,e.createToast=u.create}(Metro,m4q),function(l,r){"use strict";var c=l.utils,d={LEFT:"left",RIGHT:"right",UP:"up",DOWN:"down",IN:"in",OUT:"out",NONE:"none",AUTO:"auto",SWIPE:"swipe",PINCH:"pinch",TAP:"tap",DOUBLE_TAP:"doubletap",LONG_TAP:"longtap",HOLD:"hold",HORIZONTAL:"horizontal",VERTICAL:"vertical",ALL_FINGERS:"all",DOUBLE_TAP_THRESHOLD:10,PHASE_START:"start",PHASE_MOVE:"move",PHASE_END:"end",PHASE_CANCEL:"cancel",SUPPORTS_TOUCH:"ontouchstart"in window,SUPPORTS_POINTER_IE10:window.navigator.msPointerEnabled&&!window.navigator.pointerEnabled&&!("ontouchstart"in window),SUPPORTS_POINTER:(window.navigator.pointerEnabled||window.navigator.msPointerEnabled)&&!("ontouchstart"in window),IN_TOUCH:"intouch"},n={touchDeferred:0,fingers:1,threshold:75,cancelThreshold:null,pinchThreshold:20,maxTimeThreshold:null,fingerReleaseThreshold:250,longTapThreshold:500,doubleTapThreshold:200,triggerOnTouchEnd:!0,triggerOnTouchLeave:!1,allowPageScroll:"auto",fallbackToMouseEvents:!0,excludedElements:".no-swipe",preventDefaultEvents:!0,onSwipe:l.noop,onSwipeLeft:l.noop,onSwipeRight:l.noop,onSwipeUp:l.noop,onSwipeDown:l.noop,onSwipeStatus:l.noop_true,onPinchIn:l.noop,onPinchOut:l.noop,onPinchStatus:l.noop_true,onTap:l.noop,onDoubleTap:l.noop,onLongTap:l.noop,onHold:l.noop,onTouchCreate:l.noop};l.touchSetup=function(e){n=r.extend({},n,e)},window.metroTouchSetup,l.touchSetup(window.metroTouchSetup),l.Component("touch",{init:function(e,t){return this._super(t,e,n,{useTouchEvents:null,START_EV:null,MOVE_EV:null,END_EV:null,LEAVE_EV:null,CANCEL_EV:null,distance:0,direction:null,currentDirection:null,duration:0,startTouchesDistance:0,endTouchesDistance:0,pinchZoom:1,pinchDistance:0,pinchDirection:0,maximumsMap:null,phase:"start",fingerCount:0,fingerData:{},startTime:0,endTime:0,previousTouchEndTime:0,fingerCountAtRelease:0,doubleTapStartTime:0,singleTapTimeout:null,holdTimeout:null}),this},_create:function(){var e=this.element,t=this.options;this.useTouchEvents=d.SUPPORTS_TOUCH||d.SUPPORTS_POINTER||!this.options.fallbackToMouseEvents,this.START_EV=this.useTouchEvents?d.SUPPORTS_POINTER?d.SUPPORTS_POINTER_IE10?"MSPointerDown":"pointerdown":"touchstart":"mousedown",this.MOVE_EV=this.useTouchEvents?d.SUPPORTS_POINTER?d.SUPPORTS_POINTER_IE10?"MSPointerMove":"pointermove":"touchmove":"mousemove",this.END_EV=this.useTouchEvents?d.SUPPORTS_POINTER?d.SUPPORTS_POINTER_IE10?"MSPointerUp":"pointerup":"touchend":"mouseup",this.LEAVE_EV=this.useTouchEvents?d.SUPPORTS_POINTER?"mouseleave":null:"mouseleave",this.CANCEL_EV=d.SUPPORTS_POINTER?d.SUPPORTS_POINTER_IE10?"MSPointerCancel":"pointercancel":"touchcancel",void 0!==t.allowPageScroll||t.onSwipe===l.noop&&t.onSwipeStatus===l.noop||(t.allowPageScroll=d.NONE);try{e.on(this.START_EV,r.proxy(this.touchStart,this)),e.on(this.CANCEL_EV,r.proxy(this.touchCancel,this))}catch(e){throw new Error("Events not supported "+this.START_EV+","+this.CANCEL_EV+" on Swipe")}this._fireEvent("touch-create",{element:e})},touchStart:function(e){var t=this.element,n=this.options;if(!(this.getTouchInProgress()||0<r(e.target).closest(n.excludedElements).length)){var i,s=e,a=s.touches,o=a?a[0]:s;return this.phase=d.PHASE_START,a?this.fingerCount=a.length:!1!==n.preventDefaultEvents&&e.preventDefault(),this.distance=0,this.direction=null,this.currentDirection=null,this.pinchDirection=null,this.duration=0,this.startTouchesDistance=0,this.endTouchesDistance=0,this.pinchZoom=1,this.pinchDistance=0,this.maximumsMap=this.createMaximumsData(),this.cancelMultiFingerRelease(),this.createFingerData(0,o),!a||this.fingerCount===n.fingers||n.fingers===d.ALL_FINGERS||this.hasPinches()?(this.startTime=this.getTimeStamp(),2===this.fingerCount&&(this.createFingerData(1,a[1]),this.startTouchesDistance=this.endTouchesDistance=this.calculateTouchesDistance(this.fingerData[0].start,this.fingerData[1].start)),n.onSwipeStatus===l.noop&&n.onPinchStatus===l.noop||(i=this.triggerHandler(s,this.phase))):i=!1,!1===i?(this.phase=d.PHASE_CANCEL,this.triggerHandler(s,this.phase),i):(n.onHold!==l.noop&&(this.holdTimeout=setTimeout(r.proxy(function(){t.trigger("hold",[s.target]),n.onHold!==l.noop&&(i=c.exec(n.onHold,[s,s.target],t[0]),t.fire("hold",{event:s,target:s.target}))},this),n.longTapThreshold)),this.setTouchInProgress(!0),null)}},touchMove:function(e){var t=e;if(this.phase!==d.PHASE_END&&this.phase!==d.PHASE_CANCEL&&!this.inMultiFingerRelease()){var n,i=t.touches,s=i?i[0]:t,a=this.updateFingerData(s);if(this.endTime=this.getTimeStamp(),i&&(this.fingerCount=i.length),this.options.onHold!==l.noop&&clearTimeout(this.holdTimeout),this.phase=d.PHASE_MOVE,2===this.fingerCount&&(0===this.startTouchesDistance?(this.createFingerData(1,i[1]),this.startTouchesDistance=this.endTouchesDistance=this.calculateTouchesDistance(this.fingerData[0].start,this.fingerData[1].start)):(this.updateFingerData(i[1]),this.endTouchesDistance=this.calculateTouchesDistance(this.fingerData[0].end,this.fingerData[1].end),this.pinchDirection=this.calculatePinchDirection(this.fingerData[0].end,this.fingerData[1].end)),this.pinchZoom=this.calculatePinchZoom(this.startTouchesDistance,this.endTouchesDistance),this.pinchDistance=Math.abs(this.startTouchesDistance-this.endTouchesDistance)),this.fingerCount===this.options.fingers||this.options.fingers===d.ALL_FINGERS||!i||this.hasPinches()){if(this.direction=this.calculateDirection(a.start,a.end),this.currentDirection=this.calculateDirection(a.last,a.end),this.validateDefaultEvent(e,this.currentDirection),this.distance=this.calculateDistance(a.start,a.end),this.duration=this.calculateDuration(),this.setMaxDistance(this.direction,this.distance),n=this.triggerHandler(t,this.phase),!this.options.triggerOnTouchEnd||this.options.triggerOnTouchLeave){var o=!0;if(this.options.triggerOnTouchLeave){var r=this.getBounds(this);o=this.isInBounds(a.end,r)}!this.options.triggerOnTouchEnd&&o?this.phase=this.getNextPhase(d.PHASE_MOVE):this.options.triggerOnTouchLeave&&!o&&(this.phase=this.getNextPhase(d.PHASE_END)),this.phase!==d.PHASE_CANCEL&&this.phase!==d.PHASE_END||this.triggerHandler(t,this.phase)}}else this.phase=d.PHASE_CANCEL,this.triggerHandler(t,this.phase);!1===n&&(this.phase=d.PHASE_CANCEL,this.triggerHandler(t,this.phase))}},touchEnd:function(e){var t=e,n=t.touches;if(n){if(n.length&&!this.inMultiFingerRelease())return this.startMultiFingerRelease(t),!0;if(n.length&&this.inMultiFingerRelease())return!0}return this.inMultiFingerRelease()&&(this.fingerCount=this.fingerCountAtRelease),this.endTime=this.getTimeStamp(),this.duration=this.calculateDuration(),this.didSwipeBackToCancel()||!this.validateSwipeDistance()?(this.phase=d.PHASE_CANCEL,this.triggerHandler(t,this.phase)):this.options.triggerOnTouchEnd||!1===this.options.triggerOnTouchEnd&&this.phase===d.PHASE_MOVE?(!1!==this.options.preventDefaultEvents&&e.preventDefault(),this.phase=d.PHASE_END,this.triggerHandler(t,this.phase)):!this.options.triggerOnTouchEnd&&this.hasTap()?(this.phase=d.PHASE_END,this.triggerHandlerForGesture(t,this.phase,d.TAP)):this.phase===d.PHASE_MOVE&&(this.phase=d.PHASE_CANCEL,this.triggerHandler(t,this.phase)),this.setTouchInProgress(!1),null},touchCancel:function(){this.fingerCount=0,this.endTime=0,this.startTime=0,this.startTouchesDistance=0,this.endTouchesDistance=0,this.pinchZoom=1,this.cancelMultiFingerRelease(),this.setTouchInProgress(!1)},touchLeave:function(e){this.options.triggerOnTouchLeave&&(this.phase=this.getNextPhase(d.PHASE_END),this.triggerHandler(e,this.phase))},getNextPhase:function(e){var t=this.options,n=e,i=this.validateSwipeTime(),s=this.validateSwipeDistance(),a=this.didSwipeBackToCancel();return!i||a?n=d.PHASE_CANCEL:!s||e!==d.PHASE_MOVE||t.triggerOnTouchEnd&&!t.triggerOnTouchLeave?!s&&e===d.PHASE_END&&t.triggerOnTouchLeave&&(n=d.PHASE_CANCEL):n=d.PHASE_END,n},triggerHandler:function(e,t){var n,i=e.touches;return(this.didSwipe()||this.hasSwipes())&&(n=this.triggerHandlerForGesture(e,t,d.SWIPE)),(this.didPinch()||this.hasPinches())&&!1!==n&&(n=this.triggerHandlerForGesture(e,t,d.PINCH)),this.didDoubleTap()&&!1!==n?n=this.triggerHandlerForGesture(e,t,d.DOUBLE_TAP):this.didLongTap()&&!1!==n?n=this.triggerHandlerForGesture(e,t,d.LONG_TAP):this.didTap()&&!1!==n&&(n=this.triggerHandlerForGesture(e,t,d.TAP)),t===d.PHASE_CANCEL&&this.touchCancel(e),t===d.PHASE_END&&(i&&i.length||this.touchCancel(e)),n},triggerHandlerForGesture:function(e,t,n){var i,s=this.element,a=this.options;if(n===d.SWIPE){if(s.trigger("swipeStatus",[t,this.direction||null,this.distance||0,this.duration||0,this.fingerCount,this.fingerData,this.currentDirection]),i=c.exec(a.onSwipeStatus,[e,t,this.direction||null,this.distance||0,this.duration||0,this.fingerCount,this.fingerData,this.currentDirection],s[0]),s.fire("swipestatus",{event:e,phase:t,direction:this.direction,distance:this.distance,duration:this.duration,fingerCount:this.fingerCount,fingerData:this.fingerData,currentDirection:this.currentDirection}),!1===i)return!1;if(t===d.PHASE_END&&this.validateSwipe()){if(clearTimeout(this.singleTapTimeout),clearTimeout(this.holdTimeout),s.trigger("swipe",[this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection]),i=c.exec(a.onSwipe,[e,this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection],s[0]),s.fire("swipe",{event:e,direction:this.direction,distance:this.distance,duration:this.duration,fingerCount:this.fingerCount,fingerData:this.fingerData,currentDirection:this.currentDirection}),!1===i)return!1;switch(this.direction){case d.LEFT:s.trigger("swipeLeft",[this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection]),i=c.exec(a.onSwipeLeft,[e,this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection],s[0]),s.fire("swipeleft",{event:e,direction:this.direction,distance:this.distance,duration:this.duration,fingerCount:this.fingerCount,fingerData:this.fingerData,currentDirection:this.currentDirection});break;case d.RIGHT:s.trigger("swipeRight",[this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection]),i=c.exec(a.onSwipeRight,[e,this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection],s[0]),s.fire("swiperight",{event:e,direction:this.direction,distance:this.distance,duration:this.duration,fingerCount:this.fingerCount,fingerData:this.fingerData,currentDirection:this.currentDirection});break;case d.UP:s.trigger("swipeUp",[this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection]),i=c.exec(a.onSwipeUp,[e,this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection],s[0]),s.fire("swipeup",{event:e,direction:this.direction,distance:this.distance,duration:this.duration,fingerCount:this.fingerCount,fingerData:this.fingerData,currentDirection:this.currentDirection});break;case d.DOWN:s.trigger("swipeDown",[this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection]),i=c.exec(a.onSwipeDown,[e,this.direction,this.distance,this.duration,this.fingerCount,this.fingerData,this.currentDirection],s[0]),s.fire("swipedown",{event:e,direction:this.direction,distance:this.distance,duration:this.duration,fingerCount:this.fingerCount,fingerData:this.fingerData,currentDirection:this.currentDirection})}}}if(n===d.PINCH){if(s.trigger("pinchStatus",[t,this.pinchDirection||null,this.pinchDistance||0,this.duration||0,this.fingerCount,this.fingerData,this.pinchZoom]),i=c.exec(a.onPinchStatus,[e,t,this.pinchDirection||null,this.pinchDistance||0,this.duration||0,this.fingerCount,this.fingerData,this.pinchZoom],s[0]),s.fire("pinchstatus",{event:e,phase:t,direction:this.pinchDirection,distance:this.pinchDistance,duration:this.duration,fingerCount:this.fingerCount,fingerData:this.fingerData,zoom:this.pinchZoom}),!1===i)return!1;if(t===d.PHASE_END&&this.validatePinch())switch(this.pinchDirection){case d.IN:s.trigger("pinchIn",[this.pinchDirection||null,this.pinchDistance||0,this.duration||0,this.fingerCount,this.fingerData,this.pinchZoom]),i=c.exec(a.onPinchIn,[e,this.pinchDirection||null,this.pinchDistance||0,this.duration||0,this.fingerCount,this.fingerData,this.pinchZoom],s[0]),s.fire("pinchin",{event:e,direction:this.pinchDirection,distance:this.pinchDistance,duration:this.duration,fingerCount:this.fingerCount,fingerData:this.fingerData,zoom:this.pinchZoom});break;case d.OUT:s.trigger("pinchOut",[this.pinchDirection||null,this.pinchDistance||0,this.duration||0,this.fingerCount,this.fingerData,this.pinchZoom]),i=c.exec(a.onPinchOut,[e,this.pinchDirection||null,this.pinchDistance||0,this.duration||0,this.fingerCount,this.fingerData,this.pinchZoom],s[0]),s.fire("pinchout",{event:e,direction:this.pinchDirection,distance:this.pinchDistance,duration:this.duration,fingerCount:this.fingerCount,fingerData:this.fingerData,zoom:this.pinchZoom})}}return n===d.TAP?t!==d.PHASE_CANCEL&&t!==d.PHASE_END||(clearTimeout(this.singleTapTimeout),clearTimeout(this.holdTimeout),this.hasDoubleTap()&&!this.inDoubleTap()?(this.doubleTapStartTime=this.getTimeStamp(),this.singleTapTimeout=setTimeout(r.proxy(function(){this.doubleTapStartTime=null,i=c.exec(a.onTap,[e,e.target],s[0]),s.fire("tap",{event:e,target:e.target})},this),a.doubleTapThreshold)):(this.doubleTapStartTime=null,i=c.exec(a.onTap,[e,e.target],s[0]),s.fire("tap",{event:e,target:e.target}))):n===d.DOUBLE_TAP?t!==d.PHASE_CANCEL&&t!==d.PHASE_END||(clearTimeout(this.singleTapTimeout),clearTimeout(this.holdTimeout),this.doubleTapStartTime=null,i=c.exec(a.onDoubleTap,[e,e.target],s[0]),s.fire("doubletap",{event:e,target:e.target})):n===d.LONG_TAP&&(t!==d.PHASE_CANCEL&&t!==d.PHASE_END||(clearTimeout(this.singleTapTimeout),this.doubleTapStartTime=null,i=c.exec(a.onLongTap,[e,e.target],s[0]),s.fire("longtap",{event:e,target:e.target}))),i},validateSwipeDistance:function(){var e=!0;return null!==this.options.threshold&&(e=this.distance>=this.options.threshold),e},didSwipeBackToCancel:function(){var e=this.options,t=!1;return null!==e.cancelThreshold&&null!==this.direction&&(t=this.getMaxDistance(this.direction)-this.distance>=e.cancelThreshold),t},validatePinchDistance:function(){return null===this.options.pinchThreshold||this.pinchDistance>=this.options.pinchThreshold},validateSwipeTime:function(){var e=this.options;return!e.maxTimeThreshold||this.duration<e.maxTimeThreshold},validateDefaultEvent:function(e,t){var n=this.options;if(!1!==n.preventDefaultEvents)if(n.allowPageScroll===d.NONE)e.preventDefault();else{var i=n.allowPageScroll===d.AUTO;switch(t){case d.LEFT:(n.onSwipeLeft!==l.noop&&i||!i&&n.allowPageScroll.toLowerCase()!==d.HORIZONTAL)&&e.preventDefault();break;case d.RIGHT:(n.onSwipeRight!==l.noop&&i||!i&&n.allowPageScroll.toLowerCase()!==d.HORIZONTAL)&&e.preventDefault();break;case d.UP:(n.onSwipeUp!==l.noop&&i||!i&&n.allowPageScroll.toLowerCase()!==d.VERTICAL)&&e.preventDefault();break;case d.DOWN:(n.onSwipeDown!==l.noop&&i||!i&&n.allowPageScroll.toLowerCase()!==d.VERTICAL)&&e.preventDefault()}}},validatePinch:function(){var e=this.validateFingers(),t=this.validateEndPoint(),n=this.validatePinchDistance();return e&&t&&n},hasPinches:function(){return!!(this.options.onPinchStatus||this.options.onPinchIn||this.options.onPinchOut)},didPinch:function(){return!(!this.validatePinch()||!this.hasPinches())},validateSwipe:function(){var e=this.validateSwipeTime(),t=this.validateSwipeDistance(),n=this.validateFingers(),i=this.validateEndPoint();return!this.didSwipeBackToCancel()&&i&&n&&t&&e},hasSwipes:function(){var e=this.options;return!(e.onSwipe===l.noop&&e.onSwipeStatus===l.noop&&e.onSwipeLeft===l.noop&&e.onSwipeRight===l.noop&&e.onSwipeUp===l.noop&&e.onSwipeDown===l.noop)},didSwipe:function(){return!(!this.validateSwipe()||!this.hasSwipes())},validateFingers:function(){return this.fingerCount===this.options.fingers||this.options.fingers===d.ALL_FINGERS||!d.SUPPORTS_TOUCH},validateEndPoint:function(){return 0!==this.fingerData[0].end.x},hasTap:function(){return this.options.onTap!==l.noop},hasDoubleTap:function(){return this.options.onDoubleTap!==l.noop},hasLongTap:function(){return this.options.onLongTap!==l.noop},validateDoubleTap:function(){if(null==this.doubleTapStartTime)return!1;var e=this.getTimeStamp();return this.hasDoubleTap()&&e-this.doubleTapStartTime<=this.options.doubleTapThreshold},inDoubleTap:function(){return this.validateDoubleTap()},validateTap:function(){return(1===this.fingerCount||!d.SUPPORTS_TOUCH)&&(isNaN(this.distance)||this.distance<this.options.threshold)},validateLongTap:function(){var e=this.options;return this.duration>e.longTapThreshold&&this.distance<d.DOUBLE_TAP_THRESHOLD},didTap:function(){return!(!this.validateTap()||!this.hasTap())},didDoubleTap:function(){return!(!this.validateDoubleTap()||!this.hasDoubleTap())},didLongTap:function(){return!(!this.validateLongTap()||!this.hasLongTap())},startMultiFingerRelease:function(e){this.previousTouchEndTime=this.getTimeStamp(),this.fingerCountAtRelease=e.touches.length+1},cancelMultiFingerRelease:function(){this.previousTouchEndTime=0,this.fingerCountAtRelease=0},inMultiFingerRelease:function(){var e=!1;this.previousTouchEndTime&&this.getTimeStamp()-this.previousTouchEndTime<=this.options.fingerReleaseThreshold&&(e=!0);return e},getTouchInProgress:function(){return!0===this.element.data("intouch")},setTouchInProgress:function(e){var t=this.element;t&&(!0===e?(t.on(this.MOVE_EV,r.proxy(this.touchMove,this)),t.on(this.END_EV,r.proxy(this.touchEnd,this)),this.LEAVE_EV&&t.on(this.LEAVE_EV,r.proxy(this.touchLeave,this))):(t.off(this.MOVE_EV),t.off(this.END_EV),this.LEAVE_EV&&t.off(this.LEAVE_EV)),t.data("intouch",!0===e))},createFingerData:function(e,t){var n={start:{x:0,y:0},last:{x:0,y:0},end:{x:0,y:0}};return n.start.x=n.last.x=n.end.x=t.pageX||t.clientX,n.start.y=n.last.y=n.end.y=t.pageY||t.clientY,this.fingerData[e]=n},updateFingerData:function(e){var t=void 0!==e.identifier?e.identifier:0,n=this.getFingerData(t);return null===n&&(n=this.createFingerData(t,e)),n.last.x=n.end.x,n.last.y=n.end.y,n.end.x=e.pageX||e.clientX,n.end.y=e.pageY||e.clientY,n},getFingerData:function(e){return this.fingerData[e]||null},setMaxDistance:function(e,t){e!==d.NONE&&(t=Math.max(t,this.getMaxDistance(e)),this.maximumsMap[e].distance=t)},getMaxDistance:function(e){return this.maximumsMap[e]?this.maximumsMap[e].distance:void 0},createMaximumsData:function(){var e={};return e[d.LEFT]=this.createMaximumVO(d.LEFT),e[d.RIGHT]=this.createMaximumVO(d.RIGHT),e[d.UP]=this.createMaximumVO(d.UP),e[d.DOWN]=this.createMaximumVO(d.DOWN),e},createMaximumVO:function(e){return{direction:e,distance:0}},calculateDuration:function(){return this.endTime-this.startTime},calculateTouchesDistance:function(e,t){var n=Math.abs(e.x-t.x),i=Math.abs(e.y-t.y);return Math.round(Math.sqrt(n*n+i*i))},calculatePinchZoom:function(e,t){return(t/e*100).toFixed(2)},calculatePinchDirection:function(){return this.pinchZoom<1?d.OUT:d.IN},calculateDistance:function(e,t){return Math.round(Math.sqrt(Math.pow(t.x-e.x,2)+Math.pow(t.y-e.y,2)))},calculateAngle:function(e,t){var n=e.x-t.x,i=t.y-e.y,s=Math.atan2(i,n),a=Math.round(180*s/Math.PI);return a<0&&(a=360-Math.abs(a)),a},calculateDirection:function(e,t){if(this.comparePoints(e,t))return d.NONE;var n=this.calculateAngle(e,t);return n<=45&&0<=n?d.LEFT:n<=360&&315<=n?d.LEFT:135<=n&&n<=225?d.RIGHT:45<n&&n<135?d.DOWN:d.UP},getTimeStamp:function(){return(new Date).getTime()},getBounds:function(e){var t=(e=r(e)).offset();return{left:t.left,right:t.left+e.outerWidth(),top:t.top,bottom:t.top+e.outerHeight()}},isInBounds:function(e,t){return e.x>t.left&&e.x<t.right&&e.y>t.top&&e.y<t.bottom},comparePoints:function(e,t){return e.x===t.x&&e.y===t.y},removeListeners:function(){var e=this.element;e.off(this.START_EV),e.off(this.CANCEL_EV),e.off(this.MOVE_EV),e.off(this.END_EV),this.LEAVE_EV&&e.off(this.LEAVE_EV),this.setTouchInProgress(!1)},enable:function(){return this.disable(),this.element.on(this.START_EV,this.touchStart),this.element.on(this.CANCEL_EV,this.touchCancel),this.element},disable:function(){return this.removeListeners(),this.element},changeAttribute:function(){},destroy:function(){this.removeListeners()}}),l.touch=d}(Metro,m4q),function(t,r){"use strict";var l=t.utils,n={treeviewDeferred:0,showChildCount:!1,duration:100,onNodeClick:t.noop,onNodeDblClick:t.noop,onNodeDelete:t.noop,onNodeInsert:t.noop,onNodeClean:t.noop,onCheckClick:t.noop,onRadioClick:t.noop,onExpandNode:t.noop,onCollapseNode:t.noop,onTreeViewCreate:t.noop};t.treeViewSetup=function(e){n=r.extend({},n,e)},window.metroTreeViewSetup,t.treeViewSetup(window.metroTreeViewSetup),t.Component("tree-view",{init:function(e,t){return this._super(t,e,n),this},_create:function(){var e=this,t=this.element;this._createTree(),this._createEvents(),r.each(t.find("input"),function(){r(this).is(":checked")&&e._recheck(this)}),this._fireEvent("tree-view-create",{element:t})},_createIcon:function(e){var t,n;return n=l.isTag(e)?r(e):r("<img src='' alt=''>").attr("src",e),(t=r("<span>").addClass("icon")).html(n.outerHTML()),t},_createCaption:function(e){return r("<span>").addClass("caption").html(e)},_createToggle:function(){return r("<span>").addClass("node-toggle")},_createNode:function(e){var t;return t=r("<li>"),void 0!==e.caption&&t.prepend(this._createCaption(e.caption)),void 0!==e.icon&&t.prepend(this._createIcon(e.icon)),void 0!==e.html&&t.append(e.html),t},_createTree:function(){var i=this,e=this.element,s=this.options,t=e.find("li");e.addClass("treeview"),r.each(t,function(){var e,t,n=r(this);e=n.data("caption"),t=n.data("icon"),void 0!==e&&(0<n.children("ul").length&&!0===s.showChildCount&&(e+=" ("+n.children("ul").children("li").length+")"),n.prepend(i._createCaption(e))),void 0!==t&&n.prepend(i._createIcon(t)),0<n.children("ul").length&&(n.addClass("tree-node"),n.append(i._createToggle()),!0!==l.bool(n.attr("data-collapsed"))?n.addClass("expanded"):n.children("ul").hide())})},_createEvents:function(){var s=this,a=this.element,o=this.options;a.on(t.events.click,".node-toggle",function(e){var t=r(this).parent();s.toggleNode(t),e.preventDefault()}),a.on(t.events.click,"li > .caption",function(e){var t=r(this).parent();s.current(t),l.exec(o.onNodeClick,[t[0]],a[0]),a.fire("nodeclick",{node:t[0]}),e.preventDefault()}),a.on(t.events.dblclick,"li > .caption",function(e){var t=r(this).closest("li"),n=t.children(".node-toggle"),i=t.children("ul");(0<n.length||0<i.length)&&s.toggleNode(t),l.exec(o.onNodeDblClick,[t[0]],a[0]),a.fire("nodedblclick",{node:t[0]}),e.preventDefault()}),a.on(t.events.click,"input[type=radio]",function(){var e=r(this),t=e.is(":checked"),n=e.closest("li");s.current(n),l.exec(o.onRadioClick,[t,e[0],n[0]],a[0]),a.fire("radioclick",{checked:t,check:e[0],node:n[0]})}),a.on(t.events.click,"input[type=checkbox]",function(){var e=r(this),t=e.is(":checked"),n=e.closest("li");s._recheck(e),l.exec(o.onCheckClick,[t,e[0],n[0]],a[0]),a.fire("checkclick",{checked:t,check:e[0],node:n[0]})})},_recheck:function(e){var t,n,i,s,a=this.element;t=(e=r(e)).is(":checked"),n=e.closest("li"),this.current(n),(i=e.closest("li").find("ul input[type=checkbox]")).attr("data-indeterminate",!1),i.prop("checked",t),i.trigger("change"),s=[],r.each(a.find("input[type=checkbox]"),function(){s.push(this)}),r.each(s.reverse(),function(){var e=r(this),t=e.closest("li").children("ul").find("input[type=checkbox]").length,n=e.closest("li").children("ul").find("input[type=checkbox]").filter(function(e){return e.checked}).length;0<t&&0===n&&(e.attr("data-indeterminate",!1),e.prop("checked",!1),e.trigger("change")),0===n?e.attr("data-indeterminate",!1):0<n&&n<t?e.attr("data-indeterminate",!0):t===n&&(e.attr("data-indeterminate",!1),e.prop("checked",!0),e.trigger("change"))})},current:function(e){var t=this.element;if(void 0===e)return t.find("li.current");t.find("li").removeClass("current"),e.addClass("current")},toggleNode:function(e){var t,n=r(e),i=this.element,s=this.options,a=!n.data("collapsed");n.toggleClass("expanded"),n.data("collapsed",a),t=!0==a?"slideUp":"slideDown",a?(l.exec(s.onCollapseNode,[n[0]],i[0]),i.fire("collapsenode",{node:n[0]})):(l.exec(s.onExpandNode,[n[0]],i[0]),i.fire("expandnode",{node:n[0]})),n.children("ul")[t](s.duration)},addTo:function(e,t){var n,i,s=this.element,a=this.options;return null===e?n=s:0===(n=(e=r(e)).children("ul")).length&&(n=r("<ul>").appendTo(e),this._createToggle().appendTo(e),e.addClass("expanded")),(i=this._createNode(t)).appendTo(n),l.exec(a.onNodeInsert,[i[0],e?e[0]:null],s[0]),s.fire("nodeinsert",{node:i[0],parent:e?e[0]:null}),i},insertBefore:function(e,t){var n=this.element,i=this.options,s=this._createNode(t);return l.isNull(e)?this.addTo(e,t):(e=r(e),s.insertBefore(e),l.exec(i.onNodeInsert,[s[0],e[0]],n[0]),n.fire("nodeinsert",{node:s[0],parent:e?e[0]:null}),s)},insertAfter:function(e,t){var n=this.element,i=this.options,s=this._createNode(t);return l.isNull(e)?this.addTo(e,t):(e=r(e),s.insertAfter(e),l.exec(i.onNodeInsert,[s[0],e[0]],n[0]),n.fire("nodeinsert",{node:s[0],parent:e[0]}),s)},del:function(e){var t=this.element,n=this.options,i=(e=r(e)).closest("ul"),s=i.closest("li");l.exec(n.onNodeDelete,[e[0]],t[0]),t.fire("nodedelete",{node:e[0]}),e.remove(),0!==i.children().length||i.is(t)||(i.remove(),s.removeClass("expanded"),s.children(".node-toggle").remove())},clean:function(e){var t=this.element,n=this.options;(e=r(e)).children("ul").remove(),e.removeClass("expanded"),e.children(".node-toggle").remove(),l.exec(n.onNodeClean,[e[0]],t[0]),t.fire("nodeclean",{node:e[0]})},changeAttribute:function(){},destroy:function(){var e=this.element;return e.off(t.events.click,".node-toggle"),e.off(t.events.click,"li > .caption"),e.off(t.events.dblclick,"li > .caption"),e.off(t.events.click,"input[type=radio]"),e.off(t.events.click,"input[type=checkbox]"),e}})}(Metro,m4q),function(s,u){"use strict";var h=s.utils,t=s.colors,p={required:function(e){return Array.isArray(e)?0<e.length&&e:!!h.isValue(e)&&e.trim()},length:function(e,t){return Array.isArray(e)?e.length===parseInt(t):!(!h.isValue(t)||isNaN(t)||t<=0)&&e.trim().length===parseInt(t)},minlength:function(e,t){return Array.isArray(e)?e.length>=parseInt(t):!(!h.isValue(t)||isNaN(t)||t<=0)&&e.trim().length>=parseInt(t)},maxlength:function(e,t){return Array.isArray(e)?e.length<=parseInt(t):!(!h.isValue(t)||isNaN(t)||t<=0)&&e.trim().length<=parseInt(t)},min:function(e,t){return!(!h.isValue(t)||isNaN(t))&&(!!this.number(e)&&(!isNaN(e)&&Number(e)>=Number(t)))},max:function(e,t){return!(!h.isValue(t)||isNaN(t))&&(!!this.number(e)&&(!isNaN(e)&&Number(e)<=Number(t)))},email:function(e){return/^[a-z0-9\u007F-\uffff!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9\u007F-\uffff!#$%&'*+\/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(e)},domain:function(e){return/^((xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/.test(e)},url:function(e){return/^(?:(?:https?|ftp):\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,}))\.?)(?::\d{2,5})?(?:[/?#]\S*)?$/i.test(e)},date:function(e,t,n){return h.isNull(t)?"invalid date"!==String(new Date(e)).toLowerCase():"invalid date"!==String(e.toDate(t,n)).toLowerCase()},number:function(e){return!isNaN(e)},integer:function(e){return h.isInt(e)},float:function(e){return h.isFloat(e)},digits:function(e){return/^\d+$/.test(e)},hexcolor:function(e){return/(^#[0-9A-F]{6}$)|(^#[0-9A-F]{3}$)/i.test(e)},color:function(e){return!!h.isValue(e)&&!1!==t.color(e,t.PALETTES.STANDARD)},pattern:function(e,t){return!!h.isValue(e)&&(!!h.isValue(t)&&new RegExp(t).test(e))},compare:function(e,t){return e===t},not:function(e,t){return e!==t},notequals:function(e,t){return!h.isNull(e)&&(!h.isNull(t)&&e.trim()!==t.trim())},equals:function(e,t){return!h.isNull(e)&&(!h.isNull(t)&&e.trim()===t.trim())},custom:function(e,t){return!1!==h.isFunc(t)&&h.exec(t,[e])},is_control:function(e){return e.parent().hasClass("input")||e.parent().hasClass("select")||e.parent().hasClass("textarea")||e.parent().hasClass("checkbox")||e.parent().hasClass("switch")||e.parent().hasClass("radio")||e.parent().hasClass("spinner")},reset_state:function(e){var t=u(e);p.is_control(t)?t.parent().removeClass("invalid valid"):t.removeClass("invalid valid")},set_valid_state:function(e){var t=u(e);p.is_control(t)?t.parent().addClass("valid"):t.addClass("valid")},set_invalid_state:function(e){var t=u(e);p.is_control(t)?t.parent().addClass("invalid"):t.addClass("invalid")},reset:function(e){var t=this;return u.each(u(e).find("[data-validate]"),function(){t.reset_state(this)}),this},validate:function(e,s,t,n,a){var o=!0,r=u(e),i=void 0!==r.data("validate")?String(r.data("validate")).split(" ").map(function(e){return e.trim()}):[],l=[],c=0<r.closest("form").length;if(0===i.length)return!0;if(this.reset_state(r),r.attr("type")&&"checkbox"===r.attr("type").toLowerCase())!1===(o=-1===i.indexOf("required")||r.is(":checked"))&&l.push("required"),void 0!==s&&(s.val+=o?0:1);else if(r.attr("type")&&"radio"===r.attr("type").toLowerCase()){void 0===r.attr("name")&&(o=!0);var d="input[name="+r.attr("name")+"]:checked";o=0<u(d).length,void 0!==s&&(s.val+=o?0:1)}else u.each(i,function(){if(!1!==o){var e,t,n,i=this.split("=");e=i[0],i.shift(),t=i.join("="),-1<["compare","equals","notequals"].indexOf(e)&&(t=c?r[0].form.elements[t].value:u("[name="+t+"]").val()),"date"===e&&(t=r.attr("data-value-format"),n=r.attr("data-value-locale")),!1===(o=!1===h.isFunc(p[e])||(!0===a||"required"===e?p[e](r.val(),t,n):""===r.val().trim()||p[e](r.val(),t,n)))&&l.push(e),void 0!==s&&(s.val+=o?0:1)}});return!1===o?(this.set_invalid_state(r),void 0!==s&&s.log.push({input:r[0],name:r.attr("name"),value:r.val(),funcs:i,errors:l}),void 0!==n&&h.exec(n,[r,r.val()],r[0])):(this.set_valid_state(r),void 0!==t&&h.exec(t,[r,r.val()],r[0])),o}};s.validator=p;var n={validatorDeferred:0,submitTimeout:200,interactiveCheck:!1,clearInvalid:0,requiredMode:!0,useRequiredClass:!0,onBeforeSubmit:s.noop_true,onSubmit:s.noop,onError:s.noop,onValidate:s.noop,onErrorForm:s.noop,onValidateForm:s.noop,onValidatorCreate:s.noop};s.validatorSetup=function(e){n=u.extend({},n,e)},window.metroValidatorSetup,s.validatorSetup(window.metroValidatorSetup),s.Component("validator",{name:"Validator",init:function(e,t){return this._super(t,e,n,{_onsubmit:null,_onreset:null,result:[]}),this},_create:function(){var e=this,t=this.element,n=this.options,i=t.find("[data-validate]");t.attr("novalidate","novalidate"),u.each(i,function(){var e=u(this);-1<e.data("validate").indexOf("required")&&!0===n.useRequiredClass&&(p.is_control(e)?e.parent().addClass("required"):e.addClass("required")),!0===n.interactiveCheck&&e.on(s.events.inputchange,function(){p.validate(this,void 0,void 0,void 0,n.requiredMode)})}),this._onsubmit=null,(this._onreset=null)!==t[0].onsubmit&&(this._onsubmit=t[0].onsubmit,t[0].onsubmit=null),null!==t[0].onreset&&(this._onreset=t[0].onreset,t[0].onreset=null),t[0].onsubmit=function(){return e._submit()},t[0].onreset=function(){return e._reset()},this._fireEvent("validator-create",{element:t})},_reset:function(){p.reset(this.element),null!==this._onsubmit&&h.exec(this._onsubmit,null,this.element[0])},_submit:function(){var e=this,t=this.element,n=this.options,i=this.elem,s=t.find("[data-validate]"),a=t.find("input[type=submit], button[type=submit]"),o={val:0,log:[]},r=u.serializeToArray(t);return 0<a.length&&a.attr("disabled","disabled").addClass("disabled"),u.each(s,function(){p.validate(this,o,n.onValidate,n.onError,n.requiredMode)}),a.removeAttr("disabled").removeClass("disabled"),o.val+=!1===h.exec(n.onBeforeSubmit,[r],this.elem)?1:0,0===o.val?(h.exec(n.onValidateForm,[r],i),t.fire("validateform",{data:r}),setTimeout(function(){h.exec(n.onSubmit,[r],i),t.fire("formsubmit",{data:r}),null!==e._onsubmit&&h.exec(e._onsubmit,null,i)},n.submitTimeout)):(h.exec(n.onErrorForm,[o.log,r],i),t.fire("errorform",{log:o.log,data:r}),0<n.clearInvalid&&setTimeout(function(){u.each(s,function(){var e=u(this);p.is_control(e)?e.parent().removeClass("invalid"):e.removeClass("invalid")})},n.clearInvalid)),0===o.val},changeAttribute:function(){}})}(Metro,m4q),function(e,g){"use strict";var w=e.utils,s={duration:4e3,animationDuration:null,transitionDuration:null,transition:"fade",animation:null,slides:[],shuffle:!1,align:"center",valign:"center",loop:!0,autoplay:!0,mute:!0,cover:!0,preload:!0,timer:!0,overlay:2,color:null,volume:1,onPlay:e.noop,onPause:e.noop,onEnd:e.noop,onWalk:e.noop,onNext:e.noop,onPrev:e.noop,onJump:e.noop,onVegasCreate:e.noop};e.vegasSetup=function(e){s=g.extend({},s,e)},window.metroVegasSetup,e.vegasSetup(window.metroVegasSetup),e.Component("vegas",{videoCache:{},init:function(e,t){return this.transitions=["fade","fade2","slideLeft","slideLeft2","slideRight","slideRight2","slideUp","slideUp2","slideDown","slideDown2","zoomIn","zoomIn2","zoomOut","zoomOut2","swirlLeft","swirlLeft2","swirlRight","swirlRight2"],this.animations=["kenburns","kenburnsUp","kenburnsDown","kenburnsRight","kenburnsLeft","kenburnsUpLeft","kenburnsUpRight","kenburnsDownLeft","kenburnsDownRight"],this.support={objectFit:"objectFit"in document.body.style,video:!/(Android|webOS|Phone|iPad|iPod|BlackBerry|Windows Phone)/i.test(navigator.userAgent)},this._super(t,e,s,{slide:0,slides:null,total:0,noshow:!1,paused:!1,ended:!1,timer:null,overlay:null,first:!0,timeout:!1}),this},_create:function(){var e=this.element;this.slides=w.isObject(this.options.slides)||[],this.total=this.slides.length,this.noshow=this.total<2,this.paused=!this.options.autoplay||this.noshow,this.options.shuffle&&this.slides.shuffle(),this.options.preload&&this._preload(),this._createStructure(),this._createEvents(),this._fireEvent("vegas-create",{element:e})},_createStructure:function(){var e,t=this,n=this.element,i=this.options,s="BODY"===n[0].tagName;s||(n.css("height",n.css("height")),e=g('<div class="vegas-wrapper">').css("overflow",n.css("overflow")).css("padding",n.css("padding")),n.css("padding")||e.css("padding-top",n.css("padding-top")).css("padding-bottom",n.css("padding-bottom")).css("padding-left",n.css("padding-left")).css("padding-right",n.css("padding-right")),n.children().appendTo(e),n.clear()),n.addClass("vegas-container"),s||n.append(e),i.timer&&(this.timer=g('<div class="vegas-timer"><div class="vegas-timer-progress">'),n.append(this.timer)),i.overlay&&(this.overlay=g('<div class="vegas-overlay">').addClass("overlay"+("boolean"==typeof i.overlay||isNaN(i.overlay)?2:+i.overlay)),n.append(this.overlay)),setTimeout(function(){w.exec(i.onPlay,null,n[0]),t._goto(t.slide)},1)},_createEvents:function(){},_preload:function(){var e;for(e=0;e<this.slides.length;e++){var t=this.slides[e];t.src&&((new Image).src=this.slides[e].src),t.video&&(t.video instanceof Array?this._video(t.video):this._video(t.video.src))}},_slideShow:function(){var e=this,t=this.options;1<this.total&&!this.ended&&!this.paused&&!this.noshow&&(this.timeout=setTimeout(function(){e.next()},t.duration))},_timer:function(e){var t=this,n=this.options;clearTimeout(this.timeout),this.timer&&(this.timer.removeClass("vegas-timer-running").find("div").css("transition-duration","0ms"),this.ended||this.paused||this.noshow||e&&setTimeout(function(){t.timer.addClass("vegas-timer-running").find("div").css("transition-duration",+n.duration-100+"ms")},100))},_fadeSoundIn:function(e,t){var n=this.options;g.animate({el:e,draw:{volume:+n.volume},dur:t})},_fadeSoundOut:function(e,t){g.animate({el:e,draw:{volume:0},dur:t})},_video:function(e){var t,n,i=e.toString();return this.videoCache[i]?this.videoCache[i]:(Array.isArray(e)||(e=[e]),(t=document.createElement("video")).preload=!0,e.forEach(function(e){(n=document.createElement("source")).src=e,t.appendChild(n)}),this.videoCache[i]=t)},_goto:function(e){var t,n,i,s,a,o=this,r=this.element,l=this.options;void 0===this.slides[e]&&(e=0),this.slide=e;var c,d,u,h,p=r.children(".vegas-slide"),f=this.slides[e],m=l.cover;function v(){o._timer(!0),setTimeout(function(){p.css("transition","all "+u+"ms").addClass("vegas-transition-"+c+"-out"),p.each(function(){var e=p.find("video").get(0);e&&(e.volume=1,o._fadeSoundOut(e,u))}),t.css("transition","all "+u+"ms").addClass("vegas-transition-"+c+"-in");for(var e=0;e<p.length-1;e++)p.eq(e).remove();w.exec(l.onWalk,[o.current(!0)],r[0]),r.fire("walk",{slide:o.current(!0)}),o._slideShow()},100)}this.first&&(this.first=!1),"repeat"!==m&&(!0===m?m="cover":!1===m&&(m="contain")),c="random"===l.transition?g.random(this.transitions):l.transition?l.transition:this.transitions[0],d="random"===l.animation?g.random(this.animations):l.animation?l.animation:this.animations[0],u=l.transitionDuration?"auto"===l.transitionDuration||+l.transitionDuration>+l.duration?+l.duration:+l.transitionDuration:+l.duration,h=l.animationDuration?"auto"===l.animationDuration||+l.animationDuration>+l.duration?+l.duration:+l.animationDuration:+l.duration,t=g("<div>").addClass("vegas-slide").addClass("vegas-transition-"+c),this.support.video&&f.video?((i=f.video instanceof Array?this._video(f.video):this._video(f.video.src)).loop=f.video.loop?f.video.loop:l.loop,i.muted=f.video.mute?f.video.mute:l.mute,i.muted?i.pause():this._fadeSoundIn(i,u),a=g(i).addClass("vegas-video").css("background-color",l.color||"#000000"),this.support.objectFit?a.css("object-position",l.align+" "+l.valign).css("object-fit",m).css("width","100%").css("height","100%"):"contain"===m&&a.css("width","100%").css("height","100%"),t.append(a)):(s=new Image,n=g("<div>").addClass("vegas-slide-inner").css({backgroundImage:'url("'+f.src+'")',backgroundColor:l.color||"#000000",backgroundPosition:l.align+" "+l.valign}),"repeat"===m?n.css("background-repeat","repeat"):n.css("background-size",m),d&&n.addClass("vegas-animation-"+d).css("animation-duration",h+"ms"),t.append(n)),p.length?p.eq(p.length-1).after(t):r.prepend(t),p.css("transition","all 0ms").each(function(){this.className="vegas-slide","VIDEO"===this.tagName&&(this.className+=" vegas-video"),c&&(this.className+=" vegas-transition-"+c,this.className+=" vegas-transition-"+c+"-in")}),this._timer(!1),i?(4===i.readyState&&(i.currentTime=0),i.play(),v()):(s.src=f.src,s.complete?v():s.onload=v)},_end:function(){this.ended=this.options.autoplay,this._timer(!1),w.exec(this.options.onPlay,[this.current(!0)],this.elem),this.element.fire("end",{slide:this.current(!0)})},play:function(){this.paused&&(w.exec(this.options.onPlay,[this.current(!0)],this.elem),this.element.fire("play",{slide:this.current(!0)}),this.paused=!1,this.next())},pause:function(){this._timer(!1),this.paused=!0,w.exec(this.options.onPause,[this.current(!0)],this.elem),this.element.fire("pause",{slide:this.current(!0)})},toggle:function(){this.paused?this.play():this.pause()},playing:function(){return!this.paused&&!this.noshow},current:function(e){return e?{slide:this.slide,data:this.slides[this.slide]}:this.slide},jump:function(e){if(e<=0||e>this.slides.length||e===this.slide+1)return this;this.slide=e-1,w.exec(this.options.onJump,[this.current(!0)],this.elem),this.element.fire("jump",{slide:this.current(!0)}),this._goto(this.slide)},next:function(){var e=this.options;if(this.slide++,this.slide>=this.slides.length){if(!e.loop)return this._end();this.slide=0}w.exec(e.onNext,[this.current(!0)],this.elem),this.element.fire("next",{slide:this.current(!0)}),this._goto(this.slide)},prev:function(){var e=this.options;if(this.slide--,this.slide<0){if(!e.loop)return this.slide++,this._end();this.slide=this.slides.length-1}w.exec(e.onPrev,[this.current(!0)],this.elem),this.element.fire("prev",{slide:this.current(!0)}),this._goto(this.slide)},changeAttribute:function(e){var t=this.element,n=this.options,i=g.camelCase(e.replace("data-",""));"slides"===i?(n.slides=t.attr("data-slides"),this.slides=w.isObject(n.slides)||[],this.total=this.slides.length,this.noshow=this.total<2,this.paused=!this.options.autoplay||this.noshow):void 0!==s[i]&&(n[i]=JSON.parse(t.attr(e)))},destroy:function(){var e=this.element,t=this.options;return clearTimeout(this.timeout),e.removeClass("vegas-container"),e.find("> .vegas-slide").remove(),e.find("> .vegas-wrapper").children().appendTo(e),e.find("> .vegas-wrapper").remove(),t.timer&&this.timer.remove(),t.overlay&&this.overlay.remove(),e[0]}})}(Metro,m4q),function(u,h){"use strict";var o=u.utils,n={videoDeferred:0,src:null,poster:"",logo:"",logoHeight:32,logoWidth:"auto",logoTarget:"",volume:.5,loop:!1,autoplay:!1,fullScreenMode:u.fullScreenMode.DESKTOP,aspectRatio:u.aspectRatio.HD,controlsHide:3e3,showLoop:!0,showPlay:!0,showStop:!0,showMute:!0,showFull:!0,showStream:!0,showVolume:!0,showInfo:!0,loopIcon:"<span class='default-icon-loop'></span>",stopIcon:"<span class='default-icon-stop'></span>",playIcon:"<span class='default-icon-play'></span>",pauseIcon:"<span class='default-icon-pause'></span>",muteIcon:"<span class='default-icon-mute'></span>",volumeLowIcon:"<span class='default-icon-low-volume'></span>",volumeMediumIcon:"<span class='default-icon-medium-volume'></span>",volumeHighIcon:"<span class='default-icon-high-volume'></span>",screenMoreIcon:"<span class='default-icon-enlarge'></span>",screenLessIcon:"<span class='default-icon-shrink'></span>",onPlay:u.noop,onPause:u.noop,onStop:u.noop,onEnd:u.noop,onMetadata:u.noop,onTime:u.noop,onVideoPlayerCreate:u.noop};u.videoPlayerSetup=function(e){n=h.extend({},n,e)},window.metroVideoPlayerSetup,u.videoPlayerSetup(window.metroVideoPlayerSetup),u.Component("video-player",{init:function(e,t){return this._super(t,e,n,{fullscreen:!1,preloader:null,player:null,video:t,stream:null,volume:null,volumeBackup:0,muted:!1,fullScreenInterval:!1,isPlaying:!1,id:o.elementId("video-player")}),this},_create:function(){var e=this.element,t=this.options;!1===u.fullScreenEnabled&&(t.fullScreenMode=u.fullScreenMode.WINDOW),this._createPlayer(),this._createControls(),this._createEvents(),this._setAspectRatio(),!0===t.autoplay&&this.play(),this._fireEvent("video-player-create",{element:e,player:this.player})},_createPlayer:function(){var e=this.element,t=this.options,n=this.video,i=h("<div>").addClass("media-player video-player "+e[0].className),s=h("<div>").addClass("preloader").appendTo(i),a=h("<a>").attr("href",t.logoTarget).addClass("logo").appendTo(i);i.insertBefore(e),e.appendTo(i),h.each(["muted","autoplay","controls","height","width","loop","poster","preload"],function(){e.removeAttr(this)}),e.attr("preload","auto"),""!==t.poster&&e.attr("poster",t.poster),n.volume=t.volume,s.activity({type:"cycle",style:"color"}),s.hide(),this.preloader=s,""!==t.logo&&h("<img>").css({height:t.logoHeight,width:t.logoWidth}).attr("src",t.logo).appendTo(a),null!==t.src&&this._setSource(t.src),e[0].className="",this.player=i},_setSource:function(e){var t=this.element;t.find("source").remove(),t.removeAttr("src"),Array.isArray(e)?h.each(e,function(){void 0!==this.src&&h("<source>").attr("src",this.src).attr("type",void 0!==this.type?this.type:"").appendTo(t)}):t.attr("src",e)},_createControls:function(){var e,t=this,n=this.element,i=this.options,s=this.elem,a=h("<div>").addClass("controls").addClass(i.clsControls).insertAfter(n),o=h("<div>").addClass("stream").appendTo(a),r=h("<input>").addClass("stream-slider ultra-thin cycle-marker").appendTo(o),l=h("<div>").addClass("volume").appendTo(a),c=h("<input>").addClass("volume-slider ultra-thin cycle-marker").appendTo(l),d=h("<div>").addClass("info-box").appendTo(a);!0!==i.showInfo&&d.hide(),u.makePlugin(r,"slider",{clsMarker:"bg-red",clsHint:"bg-cyan fg-white",clsComplete:"bg-cyan",hint:!0,onStart:function(){s.paused||s.pause()},onStop:function(e){0<s.seekable.length&&(s.currentTime=(t.duration*e/100).toFixed(0)),s.paused&&0<s.currentTime&&s.play()}}),this.stream=r,!0!==i.showStream&&o.hide(),u.makePlugin(c,"slider",{clsMarker:"bg-red",clsHint:"bg-cyan fg-white",hint:!0,value:100*i.volume,onChangeValue:function(e){s.volume=e/100}}),this.volume=c,!0!==i.showVolume&&l.hide(),!0===i.showLoop&&(e=h("<button>").attr("type","button").addClass("button square loop").html(i.loopIcon).appendTo(a)),!0===i.showPlay&&h("<button>").attr("type","button").addClass("button square play").html(i.playIcon).appendTo(a),!0===i.showStop&&h("<button>").attr("type","button").addClass("button square stop").html(i.stopIcon).appendTo(a),!0===i.showMute&&h("<button>").attr("type","button").addClass("button square mute").html(i.muteIcon).appendTo(a),!0===i.showFull&&h("<button>").attr("type","button").addClass("button square full").html(i.screenMoreIcon).appendTo(a),!0===i.loop&&(e.addClass("active"),n.attr("loop","loop")),this._setVolume(),i.muted&&(t.volumeBackup=s.volume,u.getPlugin(t.volume,"slider").val(0),s.volume=0),d.html("00:00 / 00:00")},_createEvents:function(){var t=this,n=this.element,i=this.options,s=this.elem,a=this.player;n.on("loadstart",function(){t.preloader.show()}),n.on("loadedmetadata",function(){t.duration=s.duration.toFixed(0),t._setInfo(0,t.duration),o.exec(i.onMetadata,[s,a],n[0])}),n.on("canplay",function(){t._setBuffer(),t.preloader.hide()}),n.on("progress",function(){t._setBuffer()}),n.on("timeupdate",function(){var e=Math.round(100*s.currentTime/t.duration);t._setInfo(s.currentTime,t.duration),u.getPlugin(t.stream,"slider").val(e),o.exec(i.onTime,[s.currentTime,t.duration,s,a],n[0])}),n.on("waiting",function(){t.preloader.show()}),n.on("loadeddata",function(){}),n.on("play",function(){a.find(".play").html(i.pauseIcon),o.exec(i.onPlay,[s,a],n[0]),t._onMouse()}),n.on("pause",function(){a.find(".play").html(i.playIcon),o.exec(i.onPause,[s,a],n[0]),t._offMouse()}),n.on("stop",function(){u.getPlugin(t.stream,"slider").val(0),o.exec(i.onStop,[s,a],n[0]),t._offMouse()}),n.on("ended",function(){u.getPlugin(t.stream,"slider").val(0),o.exec(i.onEnd,[s,a],n[0]),t._offMouse()}),n.on("volumechange",function(){t._setVolume()}),a.on(u.events.click,".play",function(){s.paused?t.play():t.pause()}),a.on(u.events.click,".stop",function(){t.stop()}),a.on(u.events.click,".mute",function(){t._toggleMute()}),a.on(u.events.click,".loop",function(){t._toggleLoop()}),a.on(u.events.click,".full",function(){t.fullscreen=!t.fullscreen,a.find(".full").html(!0===t.fullscreen?i.screenLessIcon:i.screenMoreIcon),i.fullScreenMode===u.fullScreenMode.WINDOW?!0===t.fullscreen?a.addClass("full-screen"):a.removeClass("full-screen"):!0===t.fullscreen?(u.requestFullScreen(s),!1===t.fullScreenInterval&&(t.fullScreenInterval=setInterval(function(){!1===u.inFullScreen()&&(t.fullscreen=!1,clearInterval(t.fullScreenInterval),t.fullScreenInterval=!1,a.find(".full").html(i.screenMoreIcon))},1e3))):u.exitFullScreen()}),h(window).on(u.events.keyup,function(e){t.fullscreen&&27===e.keyCode&&a.find(".full").click()},{ns:this.id}),h(window).on(u.events.resize,function(){t._setAspectRatio()},{ns:this.id})},_onMouse:function(){var t=this.options,n=this.player;n.on(u.events.enter,function(){var e=n.find(".controls");0<t.controlsHide&&"none"===e.style("display")&&e.stop(!0).fadeIn(500,function(){e.css("display","flex")})}),n.on(u.events.leave,function(){var e=n.find(".controls");0<t.controlsHide&&1===parseInt(e.style("opacity"))&&setTimeout(function(){e.stop(!0).fadeOut(500)},t.controlsHide)})},_offMouse:function(){var e=this.player,t=this.options,n=e.find(".controls");e.off(u.events.enter),e.off(u.events.leave),0<t.controlsHide&&"none"===n.style("display")&&n.stop(!0).fadeIn(500,function(){n.css("display","flex")})},_toggleLoop:function(){var e=this.player.find(".loop");0!==e.length&&(e.toggleClass("active"),e.hasClass("active")?this.element.attr("loop","loop"):this.element.removeAttr("loop"))},_toggleMute:function(){this.muted=!this.muted,!1===this.muted?this.video.volume=this.volumeBackup:(this.volumeBackup=this.video.volume,this.video.volume=0),u.getPlugin(this.volume,"slider").val(!1===this.muted?100*this.volumeBackup:0)},_setInfo:function(e,t){this.player.find(".info-box").html(o.secondsToFormattedString(Math.round(e))+" / "+o.secondsToFormattedString(Math.round(t)))},_setBuffer:function(){var e=this.video.buffered.length?Math.round(Math.floor(this.video.buffered.end(0))/Math.floor(this.video.duration)*100):0;u.getPlugin(this.stream,"slider").buff(e)},_setVolume:function(){var e=this.video,t=this.player,n=this.options,i=t.find(".mute"),s=100*e.volume;1<s&&s<30?i.html(n.volumeLowIcon):30<=s&&s<60?i.html(n.volumeMediumIcon):60<=s&&s<=100?i.html(n.volumeHighIcon):i.html(n.muteIcon)},_setAspectRatio:function(){var e,t=this.player,n=this.options,i=t.outerWidth();switch(n.aspectRatio){case u.aspectRatio.SD:e=o.aspectRatioH(i,"4/3");break;case u.aspectRatio.CINEMA:e=o.aspectRatioH(i,"21/9");break;default:e=o.aspectRatioH(i,"16/9")}t.outerHeight(e)},aspectRatio:function(e){this.options.aspectRatio=e,this._setAspectRatio()},play:function(e){void 0!==e&&this._setSource(e),void 0===this.element.attr("src")&&0===this.element.find("source").length||(this.isPlaying=!0,this.video.play())},pause:function(){this.isPlaying=!1,this.video.pause()},resume:function(){this.video.paused&&this.play()},stop:function(){this.isPlaying=!1,this.video.pause(),this.video.currentTime=0,u.getPlugin(this.stream,"slider").val(0),this._offMouse()},setVolume:function(e){if(void 0===e)return this.video.volume;1<e&&(e/=100),this.video.volume=e,u.getPlugin(this.volume[0],"slider").val(100*e)},loop:function(){this._toggleLoop()},mute:function(){this._toggleMute()},changeAspectRatio:function(){this.options.aspectRatio=this.element.attr("data-aspect-ratio"),this._setAspectRatio()},changeSource:function(){var e=JSON.parse(this.element.attr("data-src"));this.play(e)},changeVolume:function(){var e=this.element.attr("data-volume");this.setVolume(e)},changeAttribute:function(e){switch(e){case"data-aspect-ratio":this.changeAspectRatio();break;case"data-src":this.changeSource();break;case"data-volume":this.changeVolume()}},destroy:function(){var e=this.element,t=this.player;return u.getPlugin(this.stream,"slider").destroy(),u.getPlugin(this.volume,"slider").destroy(),e.off("loadstart"),e.off("loadedmetadata"),e.off("canplay"),e.off("progress"),e.off("timeupdate"),e.off("waiting"),e.off("loadeddata"),e.off("play"),e.off("pause"),e.off("stop"),e.off("ended"),e.off("volumechange"),t.off(u.events.click,".play"),t.off(u.events.click,".stop"),t.off(u.events.click,".mute"),t.off(u.events.click,".loop"),t.off(u.events.click,".full"),h(window).off(u.events.keyup,{ns:this.id}),h(window).off(u.events.resize,{ns:this.id}),e}})}(Metro,m4q),function(d,u){"use strict";var h=d.utils,n={windowDeferred:0,hidden:!1,width:"auto",height:"auto",btnClose:!0,btnMin:!0,btnMax:!0,draggable:!0,dragElement:".window-caption .icon, .window-caption .title",dragArea:"parent",shadow:!1,icon:"",title:"Window",content:null,resizable:!0,overlay:!1,overlayColor:"transparent",overlayAlpha:.5,modal:!1,position:"absolute",checkEmbed:!0,top:"auto",left:"auto",place:"auto",closeAction:d.actions.REMOVE,customButtons:null,clsCustomButton:"",clsCaption:"",clsContent:"",clsWindow:"",_runtime:!1,minWidth:0,minHeight:0,maxWidth:0,maxHeight:0,onDragStart:d.noop,onDragStop:d.noop,onDragMove:d.noop,onCaptionDblClick:d.noop,onCloseClick:d.noop,onMaxClick:d.noop,onMinClick:d.noop,onResizeStart:d.noop,onResizeStop:d.noop,onResize:d.noop,onWindowCreate:d.noop,onShow:d.noop,onWindowDestroy:d.noop,onCanClose:d.noop_true,onClose:d.noop};d.windowSetup=function(e){n=u.extend({},n,e)},window.metroWindowSetup,d.windowSetup(window.metroWindowSetup),d.Component("window",{init:function(e,t){return this._super(t,e,n,{win:null,overlay:null,position:{top:0,left:0},hidden:!1,content:null}),this},_create:function(){var e,t,n=this,i=this.element,s=this.options,a="parent"===s.dragArea?i.parent():u(s.dragArea);!0===s.modal&&(s.btnMax=!1,s.btnMin=!1,s.resizable=!1),h.isNull(s.content)||(h.isUrl(s.content)&&h.isVideoUrl(s.content)?(s.content=h.embedUrl(s.content),i.css({height:"100%"})):!h.isQ(s.content)&&h.isFunc(s.content)&&(s.content=h.exec(s.content)),i.append(s.content)),s.content=i,!0===s._runtime&&this._runtime(i,"window"),(e=this._window(s)).addClass("no-visible"),a.append(e),!0===s.overlay&&((t=this._overlay()).appendTo(e.parent()),this.overlay=t),this.win=e,this._fireEvent("window-create",{win:this.win[0],element:i}),setTimeout(function(){n._setPosition(),!0!==s.hidden&&n.win.removeClass("no-visible"),n._fireEvent("show",{win:n.win[0],element:i})},100)},_setPosition:function(){var e,t,n,i,s=this.options,a=this.win,o="parent"===s.dragArea?a.parent():u(s.dragArea),r=o.height()/2-a[0].offsetHeight/2,l=o.width()/2-a[0].offsetWidth/2;if("auto"!==s.place){switch(s.place.toLowerCase()){case"top-left":t=e=0,i=n="auto";break;case"top-center":e=0,t=l,i=n="auto";break;case"top-right":n=e=0,i=t="auto";break;case"right-center":e=r,n=0,i=t="auto";break;case"bottom-right":n=i=0,e=t="auto";break;case"bottom-center":i=0,t=l,e=n="auto";break;case"bottom-left":t=i=0,e=n="auto";break;case"left-center":e=r,t=0,i=n="auto";break;default:e=r,t=l,n=i="auto"}a.css({top:e,left:t,bottom:i,right:n})}},_window:function(t){var e,n,i,s,a,o=this,r=t.width,l=t.height;if(e=u("<div>").addClass("window"),!0===t.modal&&e.addClass("modal"),n=u("<div>").addClass("window-caption"),i=u("<div>").addClass("window-content"),e.append(n),e.append(i),!0===t.status&&(a=u("<div>").addClass("window-status"),e.append(a)),!0===t.shadow&&e.addClass("win-shadow"),h.isValue(t.icon)&&u("<span>").addClass("icon").html(t.icon).appendTo(n),u("<span>").addClass("title").html(h.isValue(t.title)?t.title:"&nbsp;").appendTo(n),h.isNull(t.content)||(h.isQ(t.content)?t.content.appendTo(i):i.html(t.content)),(s=u("<div>").addClass("buttons")).appendTo(n),!0===t.btnMax&&u("<span>").addClass("button btn-max sys-button").appendTo(s),!0===t.btnMin&&u("<span>").addClass("button btn-min sys-button").appendTo(s),!0===t.btnClose&&u("<span>").addClass("button btn-close sys-button").appendTo(s),h.isValue(t.customButtons)){var c=[];!1!==h.isObject(t.customButtons)&&(t.customButtons=h.isObject(t.customButtons)),"string"==typeof t.customButtons&&-1<t.customButtons.indexOf("{")?c=JSON.parse(t.customButtons):"object"==typeof t.customButtons&&0<h.objectLength(t.customButtons)?c=t.customButtons:console.warn("Unknown format for custom buttons"),u.each(c,function(){var e=u("<span>");e.addClass("button btn-custom").addClass(t.clsCustomButton).addClass(this.cls).attr("tabindex",-1).html(this.html),e.data("action",this.onclick),s.prepend(e)})}return n.on(d.events.stop,".btn-custom",function(e){if(!h.isRightMouse(e)){var t=u(this),n=t.data("action");h.exec(n,[t],this)}}),e.attr("id",void 0===t.id?h.elementId("window"):t.id),e.on(d.events.dblclick,".window-caption",function(e){o.maximized(e)}),n.on(d.events.click,".btn-max, .btn-min, .btn-close",function(e){if(!h.isRightMouse(e)){var t=u(e.target);t.hasClass("btn-max")&&o.maximized(e),t.hasClass("btn-min")&&o.minimized(e),t.hasClass("btn-close")&&o.close(e)}}),!0===t.draggable&&d.makePlugin(e,"draggable",{dragContext:e[0],dragElement:t.dragElement,dragArea:t.dragArea,onDragStart:t.onDragStart,onDragStop:t.onDragStop,onDragMove:t.onDragMove}),e.addClass(t.clsWindow),n.addClass(t.clsCaption),i.addClass(t.clsContent),0===t.minWidth&&(t.minWidth=34,u.each(s.children(".btn-custom"),function(){t.minWidth+=h.hiddenElementSize(this).width}),t.btnMax&&(t.minWidth+=34),t.btnMin&&(t.minWidth+=34),t.btnClose&&(t.minWidth+=34)),0<t.minWidth&&!isNaN(t.width)&&t.width<t.minWidth&&(r=t.minWidth),0<t.minHeight&&!isNaN(t.height)&&t.height>t.minHeight&&(l=t.minHeight),!0===t.resizable&&(u("<span>").addClass("resize-element").appendTo(e),e.addClass("resizable"),d.makePlugin(e,"resizable",{minWidth:t.minWidth,minHeight:t.minHeight,maxWidth:t.maxWidth,maxHeight:t.maxHeight,resizeElement:".resize-element",onResizeStart:t.onResizeStart,onResizeStop:t.onResizeStop,onResize:t.onResize})),e.css({width:r,height:l,position:t.position,top:t.top,left:t.left}),e},_overlay:function(){var e=this.options,t=u("<div>");return t.addClass("overlay"),"transparent"===e.overlayColor?t.addClass("transparent"):t.css({background:h.hex2rgba(e.overlayColor,e.overlayAlpha)}),t},maximized:function(e){var t=this.win,n=this.element,i=this.options,s=u(e.currentTarget);t.removeClass("minimized"),t.toggleClass("maximized"),s.hasClass("window-caption")?(h.exec(i.onCaptionDblClick,[t[0]],n[0]),n.fire("captiondblclick",{win:t[0]})):(h.exec(i.onMaxClick,[t[0]],n[0]),n.fire("maxclick",{win:t[0]}))},minimized:function(){var e=this.win,t=this.element,n=this.options;e.removeClass("maximized"),e.toggleClass("minimized"),h.exec(n.onMinClick,[e[0]],t[0]),t.fire("minclick",{win:e[0]})},close:function(){var e=this,t=this.win,n=this.element,i=this.options;if(!1===h.exec(i.onCanClose,[t]))return!1;var s=0;i.onClose!==d.noop&&(s=500),h.exec(i.onClose,[t[0]],n[0]),n.fire("close",{win:t[0]}),setTimeout(function(){!0===i.modal&&t.siblings(".overlay").remove(),h.exec(i.onCloseClick,[t[0]],n[0]),n.fire("closeclick",{win:t[0]}),h.exec(i.onWindowDestroy,[t[0]],n[0]),n.fire("windowdestroy",{win:t[0]}),i.closeAction===d.actions.REMOVE?t.remove():e.hide()},s)},hide:function(){var e=this.element,t=this.options;this.win.css({display:"none"}),h.exec(t.onHide,[this.win[0]],e[0]),e.fire("hide",{win:this.win[0]})},show:function(){var e=this.element,t=this.options;this.win.removeClass("no-visible"),this.win.css({display:"flex"}),h.exec(t.onShow,[this.win[0]],e[0]),e.fire("show",{win:this.win[0]})},toggle:function(){"none"===this.win.css("display")||this.win.hasClass("no-visible")?this.show():this.hide()},isOpen:function(){return this.win.hasClass("no-visible")},min:function(e){e?this.win.addClass("minimized"):this.win.removeClass("minimized")},max:function(e){e?this.win.addClass("maximized"):this.win.removeClass("maximized")},toggleButtons:function(e){var t=this.win,n=t.find(".btn-close"),i=t.find(".btn-min"),s=t.find(".btn-max");"data-btn-close"===e&&n.toggle(),"data-btn-min"===e&&i.toggle(),"data-btn-max"===e&&s.toggle()},changeSize:function(e){var t=this.element,n=this.win;"data-width"===e&&n.css("width",t.data("width")),"data-height"===e&&n.css("height",t.data("height"))},changeClass:function(e){var t=this.element,n=this.win,i=this.options;"data-cls-window"===e&&(n[0].className="window "+(i.resizable?" resizable ":" ")+t.attr("data-cls-window")),"data-cls-caption"===e&&(n.find(".window-caption")[0].className="window-caption "+t.attr("data-cls-caption")),"data-cls-content"===e&&(n.find(".window-content")[0].className="window-content "+t.attr("data-cls-content"))},toggleShadow:function(){var e=this.element,t=this.win;!0===JSON.parse(e.attr("data-shadow"))?t.addClass("win-shadow"):t.removeClass("win-shadow")},setContent:function(e){var t,n=this.element,i=this.win,s=h.isValue(e)?e:n.attr("data-content");t=!h.isQ(s)&&h.isFunc(s)?h.exec(s):h.isQ(s)?s.html():s,i.find(".window-content").html(t)},setTitle:function(e){var t=this.element,n=this.win,i=h.isValue(e)?e:t.attr("data-title");n.find(".window-caption .title").html(i)},setIcon:function(e){var t=this.element,n=this.win,i=h.isValue(e)?e:t.attr("data-icon");n.find(".window-caption .icon").html(i)},getIcon:function(){return this.win.find(".window-caption .icon").html()},getTitle:function(){return this.win.find(".window-caption .title").html()},toggleDraggable:function(){var e=this.element,t=this.win,n=JSON.parse(e.attr("data-draggable")),i=d.getPlugin(t,"draggable");!0===n?i.on():i.off()},toggleResizable:function(){var e=this.element,t=this.win,n=JSON.parse(e.attr("data-resizable")),i=d.getPlugin(t,"resizable");!0===n?(i.on(),t.find(".resize-element").removeClass("resize-element-disabled")):(i.off(),t.find(".resize-element").addClass("resize-element-disabled"))},changeTopLeft:function(e){var t,n=this.element,i=this.win;if("data-top"===e){if(t=parseInt(n.attr("data-top")),!isNaN(t))return;i.css("top",t)}if("data-left"===e){if(t=parseInt(n.attr("data-left")),!isNaN(t))return;i.css("left",t)}},changePlace:function(e){var t=this.element,n=this.win,i=h.isValue(e)?e:t.attr("data-place");n.addClass(i)},changeAttribute:function(e){switch(e){case"data-btn-close":case"data-btn-min":case"data-btn-max":this.toggleButtons(e);break;case"data-width":case"data-height":this.changeSize(e);break;case"data-cls-window":case"data-cls-caption":case"data-cls-content":this.changeClass(e);break;case"data-shadow":this.toggleShadow();break;case"data-icon":this.setIcon();break;case"data-title":this.setTitle();break;case"data-content":this.setContent();break;case"data-draggable":this.toggleDraggable();break;case"data-resizable":this.toggleResizable();break;case"data-top":case"data-left":this.changeTopLeft(e);break;case"data-place":this.changePlace()}},destroy:function(){return this.element}}),d.window={isWindow:function(e){return h.isMetroObject(e,"window")},min:function(e,t){if(!this.isWindow(e))return!1;d.getPlugin(e,"window").min(t)},max:function(e,t){if(!this.isWindow(e))return!1;d.getPlugin(e,"window").max(t)},show:function(e){if(!this.isWindow(e))return!1;d.getPlugin(e,"window").show()},hide:function(e){if(!this.isWindow(e))return!1;d.getPlugin(e,"window").hide()},toggle:function(e){if(!this.isWindow(e))return!1;d.getPlugin(e,"window").toggle()},isOpen:function(e){return!!this.isWindow(e)&&d.getPlugin(e,"window").isOpen()},close:function(e){if(!this.isWindow(e))return!1;d.getPlugin(e,"window").close()},create:function(e){var t;t=u("<div>").appendTo(u("body"));var n=u.extend({},{},void 0!==e?e:{});return n._runtime=!0,d.makePlugin(t,"window",n)}}}(Metro,m4q),function(s,d){"use strict";var u=s.utils,n={wizardDeferred:0,start:1,finish:0,iconHelp:"<span class='default-icon-help'></span>",iconPrev:"<span class='default-icon-left-arrow'></span>",iconNext:"<span class='default-icon-right-arrow'></span>",iconFinish:"<span class='default-icon-check'></span>",buttonMode:"cycle",buttonOutline:!0,duration:300,clsWizard:"",clsActions:"",clsHelp:"",clsPrev:"",clsNext:"",clsFinish:"",onPage:s.noop,onNextPage:s.noop,onPrevPage:s.noop,onFirstPage:s.noop,onLastPage:s.noop,onFinishPage:s.noop,onHelpClick:s.noop,onPrevClick:s.noop,onNextClick:s.noop,onFinishClick:s.noop,onBeforePrev:s.noop_true,onBeforeNext:s.noop_true,onWizardCreate:s.noop};s.wizardSetup=function(e){n=d.extend({},n,e)},window.metroWizardSetup,s.wizardSetup(window.metroWizardSetup),s.Component("wizard",{init:function(e,t){return this._super(t,e,n,{id:u.elementId("wizard")}),this},_create:function(){var e=this.element;this._createWizard(),this._createEvents(),this._fireEvent("wizard-create",{element:e})},_createWizard:function(){var e,t=this.element,n=this.options;t.addClass("wizard").addClass(n.view).addClass(n.clsWizard),e=d("<div>").addClass("action-bar").addClass(n.clsActions).appendTo(t);var i="button"===n.buttonMode?"":n.buttonMode;!0===n.buttonOutline&&(i+=" outline"),!1!==n.iconHelp&&d("<button>").attr("type","button").addClass("button wizard-btn-help").addClass(i).addClass(n.clsHelp).html(u.isTag(n.iconHelp)?n.iconHelp:d("<img>").attr("src",n.iconHelp)).appendTo(e),!1!==n.iconPrev&&d("<button>").attr("type","button").addClass("button wizard-btn-prev").addClass(i).addClass(n.clsPrev).html(u.isTag(n.iconPrev)?n.iconPrev:d("<img>").attr("src",n.iconPrev)).appendTo(e),!1!==n.iconNext&&d("<button>").attr("type","button").addClass("button wizard-btn-next").addClass(i).addClass(n.clsNext).html(u.isTag(n.iconNext)?n.iconNext:d("<img>").attr("src",n.iconNext)).appendTo(e),!1!==n.iconFinish&&d("<button>").attr("type","button").addClass("button wizard-btn-finish").addClass(i).addClass(n.clsFinish).html(u.isTag(n.iconFinish)?n.iconFinish:d("<img>").attr("src",n.iconFinish)).appendTo(e),this.toPage(n.start),this._setHeight()},_setHeight:function(){var e=this.element,t=e.children("section"),n=0;t.children(".page-content").css("max-height","none"),d.each(t,function(){var e=d(this).height();n<parseInt(e)&&(n=e)}),e.height(n)},_createEvents:function(){var t=this,n=this.element,i=this.options;n.on(s.events.click,".wizard-btn-help",function(){var e=n.children("section").get(t.current-1);u.exec(i.onHelpClick,[t.current,e,n[0]]),n.fire("helpclick",{index:t.current,page:e})}),n.on(s.events.click,".wizard-btn-prev",function(){t.prev();var e=n.children("section").get(t.current-1);u.exec(i.onPrevClick,[t.current,e],n[0]),n.fire("prevclick",{index:t.current,page:e})}),n.on(s.events.click,".wizard-btn-next",function(){t.next();var e=n.children("section").get(t.current-1);u.exec(i.onNextClick,[t.current,e],n[0]),n.fire("nextclick",{index:t.current,page:e})}),n.on(s.events.click,".wizard-btn-finish",function(){var e=n.children("section").get(t.current-1);u.exec(i.onFinishClick,[t.current,e],n[0]),n.fire("finishclick",{index:t.current,page:e})}),n.on(s.events.click,".complete",function(){var e=d(this).index()+1;t.toPage(e)}),d(window).on(s.events.resize,function(){t._setHeight()},{ns:this.id})},next:function(){var e=this.element,t=this.options,n=e.children("section"),i=d(e.children("section").get(this.current-1));this.current+1>n.length||!1===u.exec(t.onBeforeNext,[this.current,i,e])||(this.current++,this.toPage(this.current),i=d(e.children("section").get(this.current-1)),u.exec(t.onNextPage,[this.current,i[0]],e[0]),e.fire("nextpage",{index:this.current,page:i[0]}))},prev:function(){var e=this.element,t=this.options,n=d(e.children("section").get(this.current-1));this.current-1!=0&&!1!==u.exec(t.onBeforePrev,[this.current,n,e])&&(this.current--,this.toPage(this.current),n=d(e.children("section").get(this.current-1)),u.exec(t.onPrevPage,[this.current,n[0]],e[0]),e.fire("prevpage",{index:this.current,page:n[0]}))},last:function(){var e,t=this.element,n=this.options;this.toPage(t.children("section").length),e=d(t.children("section").get(this.current-1)),u.exec(n.onLastPage,[this.current,e[0]],t[0]),t.fire("lastpage",{index:this.current,page:e[0]})},first:function(){var e,t=this.element,n=this.options;this.toPage(1),e=d(t.children("section").get(0)),u.exec(n.onFirstPage,[this.current,e[0]],t[0]),t.fire("firstpage",{index:this.current,page:e[0]})},toPage:function(e){var t=this.element,n=this.options,i=d(t.children("section").get(e-1)),s=t.children("section"),a=t.find(".action-bar");if(0!==i.length){var o=t.find(".wizard-btn-finish").addClass("disabled"),r=t.find(".wizard-btn-next").addClass("disabled"),l=t.find(".wizard-btn-prev").addClass("disabled");this.current=e,t.children("section").removeClass("complete current").removeClass(n.clsCurrent).removeClass(n.clsComplete),i.addClass("current").addClass(n.clsCurrent),i.prevAll().addClass("complete").addClass(n.clsComplete);var c=0===t.children("section.complete").length?0:parseInt(u.getStyleOne(t.children("section.complete")[0],"border-left-width"));a.animate({draw:{left:t.children("section.complete").length*c+41},dur:n.duration}),(this.current===s.length||0<n.finish&&this.current>=n.finish)&&o.removeClass("disabled"),0<parseInt(n.finish)&&this.current===parseInt(n.finish)&&(u.exec(n.onFinishPage,[this.current,i[0]],t[0]),t.fire("finishpage",{index:this.current,page:i[0]})),this.current<s.length&&r.removeClass("disabled"),1<this.current&&l.removeClass("disabled"),u.exec(n.onPage,[this.current,i[0]],t[0]),t.fire("page",{index:this.current,page:i[0]})}},changeAttribute:function(){},destroy:function(){var e=this.element;return e.off(s.events.click,".wizard-btn-help"),e.off(s.events.click,".wizard-btn-prev"),e.off(s.events.click,".wizard-btn-next"),e.off(s.events.click,".wizard-btn-finish"),e.off(s.events.click,".complete"),d(window).off(s.events.resize,{ns:this.id}),e}})}(Metro,m4q);

/* WEBPACK VAR INJECTION */}.call(this, __webpack_require__(5).setImmediate))

/***/ }),
/* 5 */
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(global) {var scope = (typeof global !== "undefined" && global) ||
            (typeof self !== "undefined" && self) ||
            window;
var apply = Function.prototype.apply;

// DOM APIs, for completeness

exports.setTimeout = function() {
  return new Timeout(apply.call(setTimeout, scope, arguments), clearTimeout);
};
exports.setInterval = function() {
  return new Timeout(apply.call(setInterval, scope, arguments), clearInterval);
};
exports.clearTimeout =
exports.clearInterval = function(timeout) {
  if (timeout) {
    timeout.close();
  }
};

function Timeout(id, clearFn) {
  this._id = id;
  this._clearFn = clearFn;
}
Timeout.prototype.unref = Timeout.prototype.ref = function() {};
Timeout.prototype.close = function() {
  this._clearFn.call(scope, this._id);
};

// Does not start the time, just sets up the members needed.
exports.enroll = function(item, msecs) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = msecs;
};

exports.unenroll = function(item) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = -1;
};

exports._unrefActive = exports.active = function(item) {
  clearTimeout(item._idleTimeoutId);

  var msecs = item._idleTimeout;
  if (msecs >= 0) {
    item._idleTimeoutId = setTimeout(function onTimeout() {
      if (item._onTimeout)
        item._onTimeout();
    }, msecs);
  }
};

// setimmediate attaches itself to the global object
__webpack_require__(6);
// On some exotic environments, it's not clear which object `setimmediate` was
// able to install onto.  Search each possibility in the same order as the
// `setimmediate` library.
exports.setImmediate = (typeof self !== "undefined" && self.setImmediate) ||
                       (typeof global !== "undefined" && global.setImmediate) ||
                       (this && this.setImmediate);
exports.clearImmediate = (typeof self !== "undefined" && self.clearImmediate) ||
                         (typeof global !== "undefined" && global.clearImmediate) ||
                         (this && this.clearImmediate);

/* WEBPACK VAR INJECTION */}.call(this, __webpack_require__(1)))

/***/ }),
/* 6 */
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(global, process) {(function (global, undefined) {
    "use strict";

    if (global.setImmediate) {
        return;
    }

    var nextHandle = 1; // Spec says greater than zero
    var tasksByHandle = {};
    var currentlyRunningATask = false;
    var doc = global.document;
    var registerImmediate;

    function setImmediate(callback) {
      // Callback can either be a function or a string
      if (typeof callback !== "function") {
        callback = new Function("" + callback);
      }
      // Copy function arguments
      var args = new Array(arguments.length - 1);
      for (var i = 0; i < args.length; i++) {
          args[i] = arguments[i + 1];
      }
      // Store and register the task
      var task = { callback: callback, args: args };
      tasksByHandle[nextHandle] = task;
      registerImmediate(nextHandle);
      return nextHandle++;
    }

    function clearImmediate(handle) {
        delete tasksByHandle[handle];
    }

    function run(task) {
        var callback = task.callback;
        var args = task.args;
        switch (args.length) {
        case 0:
            callback();
            break;
        case 1:
            callback(args[0]);
            break;
        case 2:
            callback(args[0], args[1]);
            break;
        case 3:
            callback(args[0], args[1], args[2]);
            break;
        default:
            callback.apply(undefined, args);
            break;
        }
    }

    function runIfPresent(handle) {
        // From the spec: "Wait until any invocations of this algorithm started before this one have completed."
        // So if we're currently running a task, we'll need to delay this invocation.
        if (currentlyRunningATask) {
            // Delay by doing a setTimeout. setImmediate was tried instead, but in Firefox 7 it generated a
            // "too much recursion" error.
            setTimeout(runIfPresent, 0, handle);
        } else {
            var task = tasksByHandle[handle];
            if (task) {
                currentlyRunningATask = true;
                try {
                    run(task);
                } finally {
                    clearImmediate(handle);
                    currentlyRunningATask = false;
                }
            }
        }
    }

    function installNextTickImplementation() {
        registerImmediate = function(handle) {
            process.nextTick(function () { runIfPresent(handle); });
        };
    }

    function canUsePostMessage() {
        // The test against `importScripts` prevents this implementation from being installed inside a web worker,
        // where `global.postMessage` means something completely different and can't be used for this purpose.
        if (global.postMessage && !global.importScripts) {
            var postMessageIsAsynchronous = true;
            var oldOnMessage = global.onmessage;
            global.onmessage = function() {
                postMessageIsAsynchronous = false;
            };
            global.postMessage("", "*");
            global.onmessage = oldOnMessage;
            return postMessageIsAsynchronous;
        }
    }

    function installPostMessageImplementation() {
        // Installs an event handler on `global` for the `message` event: see
        // * https://developer.mozilla.org/en/DOM/window.postMessage
        // * http://www.whatwg.org/specs/web-apps/current-work/multipage/comms.html#crossDocumentMessages

        var messagePrefix = "setImmediate$" + Math.random() + "$";
        var onGlobalMessage = function(event) {
            if (event.source === global &&
                typeof event.data === "string" &&
                event.data.indexOf(messagePrefix) === 0) {
                runIfPresent(+event.data.slice(messagePrefix.length));
            }
        };

        if (global.addEventListener) {
            global.addEventListener("message", onGlobalMessage, false);
        } else {
            global.attachEvent("onmessage", onGlobalMessage);
        }

        registerImmediate = function(handle) {
            global.postMessage(messagePrefix + handle, "*");
        };
    }

    function installMessageChannelImplementation() {
        var channel = new MessageChannel();
        channel.port1.onmessage = function(event) {
            var handle = event.data;
            runIfPresent(handle);
        };

        registerImmediate = function(handle) {
            channel.port2.postMessage(handle);
        };
    }

    function installReadyStateChangeImplementation() {
        var html = doc.documentElement;
        registerImmediate = function(handle) {
            // Create a <script> element; its readystatechange event will be fired asynchronously once it is inserted
            // into the document. Do so, thus queuing up the task. Remember to clean up once it's been called.
            var script = doc.createElement("script");
            script.onreadystatechange = function () {
                runIfPresent(handle);
                script.onreadystatechange = null;
                html.removeChild(script);
                script = null;
            };
            html.appendChild(script);
        };
    }

    function installSetTimeoutImplementation() {
        registerImmediate = function(handle) {
            setTimeout(runIfPresent, 0, handle);
        };
    }

    // If supported, we should attach to the prototype of global, since that is where setTimeout et al. live.
    var attachTo = Object.getPrototypeOf && Object.getPrototypeOf(global);
    attachTo = attachTo && attachTo.setTimeout ? attachTo : global;

    // Don't get fooled by e.g. browserify environments.
    if ({}.toString.call(global.process) === "[object process]") {
        // For Node.js before 0.9
        installNextTickImplementation();

    } else if (canUsePostMessage()) {
        // For non-IE10 modern browsers
        installPostMessageImplementation();

    } else if (global.MessageChannel) {
        // For web workers, where supported
        installMessageChannelImplementation();

    } else if (doc && "onreadystatechange" in doc.createElement("script")) {
        // For IE 6–8
        installReadyStateChangeImplementation();

    } else {
        // For older browsers
        installSetTimeoutImplementation();
    }

    attachTo.setImmediate = setImmediate;
    attachTo.clearImmediate = clearImmediate;
}(typeof self === "undefined" ? typeof global === "undefined" ? this : global : self));

/* WEBPACK VAR INJECTION */}.call(this, __webpack_require__(1), __webpack_require__(7)))

/***/ }),
/* 7 */
/***/ (function(module, exports) {

// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };


/***/ })
/******/ ])["default"];
});