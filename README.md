The base64 custom search command is a command for base64 encoding and decoding. 
Includes a command for base64 encoded content in MIME encoded data.

This major revision maintains compatibility with previous commands. Fixes are listed in the version notes.

### base64 command

```
... | base64 field=your_field [action=(encode|decode)] [mode=(replace|append)] [backslash_escape=(True|False)] [encoding="charset_name"] [alphabet="custom_alphabet"] [recurse=(True|False)]  [suppress_error=(True|False)]
```

* field : field to encode or decode.
* action : encode (default) or decode the content. Optional.
* mode : replace the existing field content (default) or create a new field named base64 (mode append). Optional.
* backslash_escape : escape non-ASCII and non-printable content (default). Optional.
* encoding : decode output with specified encoding, falls back to backslash_escape if charset is not found See Python standard encodings for your . Optional.
* alphabet : string (not field) for alternate base64 alphabet. Optional.
* recurse : Attempt to continue decoding if the output contains base64 characters. Optional.
* suppress_error : do not raise errors if set to True. Optional, default is False.

**Note on decoding:**

While the input string can be anything for the encoding operation, it should respect the alphabet `[A-Za-z0-9+/=]` if a custom alphabet is not used. 
If the input string length is incorrect, the last returned character may be incorrect. 
If other format requirements are not respected, the command may throw errors (except if you set the flag `suppress_error`). 
When errors are suppressed, the output array length will not match the input.

In the following example, we assume we are working on [proxy/web logs](https://docs.splunk.com/Documentation/CIM/latest/User/Web) and those will contain a field `url`, `uri_path` or `uri_query`. Some of the `uri_query` fields will contain an argument `plop` which refers to base64 encoded data.

So, to get it working:

* find the `plop` query string
* extract the base64 content ([rex](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rex) command)
* [urldecode](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/TextFunctions#urldecode.28X.29) the query string 
* decode the base64 content

Here is one way of doing it in Splunk:

... your search to get field `uri_query` for example...
```
`cim_Web_indexes` "plop=*" 
| rex field=uri_query "\bplop=(?P<content_to_decode>[^&#?;]+)" 
| eval content_to_decode = urldecode(content_to_decode) 
| base64 field="content_to_decode" action="decode" mode="append" 
```

Or if the `plop` query string uses the URL safe base64 alphabet:
```
... 
| base64 field="content_to_decode" action="decode" mode="append" alphabet="-_"
```

Or if the `plop` query string uses a ROT13 base64 alphabet:
```
... 
| base64 field="content_to_decode" action="decode" mode="append" alphabet="NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/="
```

### mimedecode command

```
... | mimedecode field=your_field [mode=(replace|append)] [suppress_error=(True|False)]
```

* field : field to decode.
* mode : replace the existing field content (default) or create a new field named base64 (mode append). Optional.
* suppress_error : do not raise errors if set to True. Optional, default is False.

A simple example to decode likely encoded header field, with a very naive error check:
```
mime_header="=?*"
| eval mime_header = if(match(mime_header, "\?=$"), mime_header, mime_header . "?=") 
| mimedecode field="mime_header" mode="append"
```

**Note on decoding:**

No special error handling outside is provided for partial data. If partial data needs to be decoded, correct the data with an `eval` or `rex mode=sed` command before executing the command.


### Lookup versions

Both commands can be executed as external lookups with fewer options.

```
| lookup base64 encoded AS your_field OUTPUT decoded AS your_decoded_field
```

```
| lookup mimedecode encoded AS your_field OUTPUT decoded AS your_decoded_field
```

#### Support

This is an open source project, no support provided, public repository available.

https://github.com/malvidin/base64

*The modified splunklib will be removed when the related issue with leading spaces is resolved.*

### History
**v2.0.2**
- Add base64 resursive decoding
- Support base64 altchars
- Add multivalue support for base64
- Merge multivalues for MIME 
- Override encoding if null bytes found 

**v2.0.1**
- Cleaner output
- Better option validation
- Escape null bytes from results

**v2.0**
- Forked from Cédric le Roux's Base64 app (1922) with permission 
- Avoid errors by adding padding
- Less ambiguous escaped output
- Optional charset when decoding
- Lookups with default options
- Return original event if input field does not exist
- MIME decoding for base64 encoded MIME
- Workaround for leading spaces

**v1.1**
- non printable characters are presented as hexadecimal when decoding (ex: `base64=<%PDF\x00\x00`).

**v1.0**
- Initial release
