"""
requests.models
~~~~~~~~~~~~~~~

该模块包含了驱动 Requests 的主要对象。
"""
import datetime

# 现在就导入 encoding ，以避免之后在线程中隐式导入。
# 在标准库在ZIP文件中，如在 Embedded Python 中，
# 线程中的隐式导入可能导致 LookupError。
# 请参阅 https://github.com/psf/requests/issues/3578.
import encodings.idna  # noqa: F401
from io import UnsupportedOperation

from urllib3.exceptions import (
    DecodeError,
    LocationParseError,
    ProtocolError,
    ReadTimeoutError,
    SSLError,
)
from urllib3.fields import RequestField
from urllib3.filepost import encode_multipart_formdata
from urllib3.util import parse_url

from ._internal_utils import to_native_string, unicode_is_ascii
from .auth import HTTPBasicAuth
from .compat import (
    Callable,
    JSONDecodeError,
    Mapping,
    basestring,
    builtin_str,
    chardet,
    cookielib,
)
from .compat import json as complexjson
from .compat import urlencode, urlsplit, urlunparse
from .cookies import _copy_cookie_jar, cookiejar_from_dict, get_cookie_header
from .exceptions import (
    ChunkedEncodingError,
    ConnectionError,
    ContentDecodingError,
    HTTPError,
    InvalidJSONError,
    InvalidURL,
)
from .exceptions import JSONDecodeError as RequestsJSONDecodeError
from .exceptions import MissingSchema
from .exceptions import SSLError as RequestsSSLError
from .exceptions import StreamConsumedError
from .hooks import default_hooks
from .status_codes import codes
from .structures import CaseInsensitiveDict
from .utils import (
    check_header_validity,
    get_auth_from_url,
    guess_filename,
    guess_json_utf,
    iter_slices,
    parse_header_links,
    requote_uri,
    stream_decode_response_unicode,
    super_len,
    to_key_val_list,
)

#: 指示可自动处理的重定向的HTTP状态码组。
REDIRECT_STATI = (
    codes.moved,  # 301
    codes.found,  # 302
    codes.other,  # 303
    codes.temporary_redirect,  # 307
    codes.permanent_redirect,  # 308
)

DEFAULT_REDIRECT_LIMIT = 30
CONTENT_CHUNK_SIZE = 10 * 1024
ITER_CHUNK_SIZE = 512


class RequestEncodingMixin:
    @property
    def path_url(self):
        """构建要使用的路径URL。"""

        url = []

        p = urlsplit(self.url)

        path = p.path
        if not path:
            path = "/"

        url.append(path)

        query = p.query
        if query:
            url.append("?")
            url.append(query)

        return "".join(url)

    @staticmethod
    def _encode_params(data):
        """在一段数据中编码参数。

        当参数以字典或2元组的列表形式传入时，可以成功编码参数。
        如果数据是2元组的列表，会保留顺序，但如果参数以字典形式提供，顺序是任意的。
        """

        if isinstance(data, (str, bytes)):
            return data
        elif hasattr(data, "read"):
            return data
        elif hasattr(data, "__iter__"):
            result = []
            for k, vs in to_key_val_list(data):
                if isinstance(vs, basestring) or not hasattr(vs, "__iter__"):
                    vs = [vs]
                for v in vs:
                    if v is not None:
                        result.append(
                            (
                                k.encode("utf-8") if isinstance(k, str) else k,
                                v.encode("utf-8") if isinstance(v, str) else v,
                            )
                        )
            return urlencode(result, doseq=True)
        else:
            return data

    @staticmethod
    def _encode_files(files, data):
        """为 multipart/form-data 请求构建 body。

        当文件以字典或元组列表的形式传递时，可以成功编码文件。
        如果数据是元组列表，会保留顺序，但如果参数以字典形式提供，顺序是任意的。
        元组可以是 2-元组 (filename, fileobj)，3-元组 (filename, fileobj, contentype)
        或 4-元组 (filename, fileobj, contentype, custom_headers)。
        """
        if not files:
            raise ValueError("必须提供文件。")
        elif isinstance(data, basestring):
            raise ValueError("数据不得是字符串。")

        new_fields = []
        fields = to_key_val_list(data or {})
        files = to_key_val_list(files or {})

        for field, val in fields:
            if isinstance(val, basestring) or not hasattr(val, "__iter__"):
                val = [val]
            for v in val:
                if v is not None:
                    # 不要在字节串上调用 str(): 在 Py3，这会引发错误。
                    if not isinstance(v, bytes):
                        v = str(v)

                    new_fields.append(
                        (
                            field.decode("utf-8")
                            if isinstance(field, bytes)
                            else field,
                            v.encode("utf-8") if isinstance(v, str) else v,
                        )
                    )

        for k, v in files:
            # 支持显式文件名
            ft = None
            fh = None
            if isinstance(v, (tuple, list)):
                if len(v) == 2:
                    fn, fp = v
                elif len(v) == 3:
                    fn, fp, ft = v
                else:
                    fn, fp, ft, fh = v
            else:
                fn = guess_filename(v) or k
                fp = v

            if isinstance(fp, (str, bytes, bytearray)):
                fdata = fp
            elif hasattr(fp, "read"):
                fdata = fp.read()
            elif fp is None:
                continue
            else:
                fdata = fp

            rf = RequestField(name=k, data=fdata, filename=fn, headers=fh)
            rf.make_multipart(content_type=ft)
            new_fields.append(rf)

        body, content_type = encode_multipart_formdata(new_fields)

        return body, content_type


class RequestHooksMixin:
    def register_hook(self, event, hook):
        """正确地注册一个钩子。"""

        if event not in self.hooks:
            raise ValueError(f'指定了不受支持的事件，事件名为 "{event}"')

        if isinstance(hook, Callable):
            self.hooks[event].append(hook)
        elif hasattr(hook, "__iter__"):
            self.hooks[event].extend(h for h in hook if isinstance(h, Callable))

    def deregister_hook(self, event, hook):
        """取消注册先前注册的钩子。
        如果钩子存在，返回 True；否则，返回 False。
        """

        try:
            self.hooks[event].remove(hook)
            return True
        except ValueError:
            return False


class Request(RequestHooksMixin):
    """用户创建的 :class:`Request <Request>` 对象。

    用于准备一个 :class:`PreparedRequest <PreparedRequest>`，该请求将发送到服务器。

    :param method: 要使用的HTTP方法。
    :param url: 要发送的URL。
    :param headers: 要发送的头部字典。
    :param files: 要进行多部分上传的 {文件名: 文件对象} 字典。
    :param data: 要附加到请求的 body。如果提供了一个字典或
        元组列表 ``[(key, value)]``，将进行表单编码。
    :param json: 要附加到请求的 json（如果没有指定文件或数据）。
    :param params: 要附加到URL的参数。如果提供了一个字典或
        元组列表 ``[(key, value)]``，将进行表单编码。
    :param auth: Auth处理器或（用户，密码）元组。
    :param cookies: 要附加到此请求的 cookies 字典或 CookieJar。
    :param hooks: 回调钩子的字典，供内部使用。

    用法::

      >>> import requests
      >>> req = requests.Request('GET', 'https://httpbin.org/get')
      >>> req.prepare()
      <PreparedRequest [GET]>
    """

    def __init__(
        self,
        method=None,
        url=None,
        headers=None,
        files=None,
        data=None,
        params=None,
        auth=None,
        cookies=None,
        hooks=None,
        json=None,
    ):
        # 默认为 dict 参数的空字典。
        data = [] if data is None else data
        files = [] if files is None else files
        headers = {} if headers is None else headers
        params = {} if params is None else params
        hooks = {} if hooks is None else hooks

        self.hooks = default_hooks()
        for k, v in list(hooks.items()):
            self.register_hook(event=k, hook=v)

        self.method = method
        self.url = url
        self.headers = headers
        self.files = files
        self.data = data
        self.json = json
        self.params = params
        self.auth = auth
        self.cookies = cookies

    def __repr__(self):
        return f"<Request [{self.method}]>"

    def prepare(self):
        """构造一个 :class:`PreparedRequest <PreparedRequest>` 以进行传输并返回它。"""
        p = PreparedRequest()
        p.prepare(
            method=self.method,
            url=self.url,
            headers=self.headers,
            files=self.files,
            data=self.data,
            json=self.json,
            params=self.params,
            auth=self.auth,
            cookies=self.cookies,
            hooks=self.hooks,
        )
        return p


class PreparedRequest(RequestEncodingMixin, RequestHooksMixin):
    """完全可变的 :class:`PreparedRequest <PreparedRequest>` 对象，
    包含将发送到服务器的确切字节。

    实例是由 :class:`Request <Request>` 对象生成的，
    不应手动实例化；否则可能产生不良效果。

    用法::

      >>> import requests
      >>> req = requests.Request('GET', 'https://httpbin.org/get')
      >>> r = req.prepare()
      >>> r
      <PreparedRequest [GET]>

      >>> s = requests.Session()
      >>> s.send(r)
      <Response [200]>
    """

    def __init__(self):
        #: 将发送到服务器的HTTP动词。
        self.method = None
        #: HTTP URL，将发送请求到此 URL。
        self.url = None
        #: HTTP头部的字典。
        self.headers = None
        # 创建Cookie头部的 `CookieJar` 将在调用 prepare_cookies 后存储在这里
        self._cookies = None
        #: 将发送到服务器的请求体。
        self.body = None
        #: 回调钩子的字典，供内部使用。
        self.hooks = default_hooks()
        #: 可读的类文件体的开始位置的整数。
        self._body_position = None

    def prepare(
        self,
        method=None,
        url=None,
        headers=None,
        files=None,
        data=None,
        params=None,
        auth=None,
        cookies=None,
        hooks=None,
        json=None,
    ):
        """使用给定的参数准备整个请求。"""

        self.prepare_method(method)
        self.prepare_url(url, params)
        self.prepare_headers(headers)
        self.prepare_cookies(cookies)
        self.prepare_body(data, files, json)
        self.prepare_auth(auth, url)

        # 注意prepare_auth必须是最后一个，以使诸如OAuth之类的认证方案
        # 能够在完全准备的请求上工作。

        # 这必须在 prepare_auth 之后。验证器可能会添加一个钩子
        self.prepare_hooks(hooks)

    def __repr__(self):
        return f"<PreparedRequest [{self.method}]>"

    def copy(self):
        p = PreparedRequest()
        p.method = self.method
        p.url = self.url
        p.headers = self.headers.copy() if self.headers is not None else None
        p._cookies = _copy_cookie_jar(self._cookies)
        p.body = self.body
        p.hooks = self.hooks
        p._body_position = self._body_position
        return p

    def prepare_method(self, method):
        """准备给定的HTTP方法。"""
        self.method = method
        if self.method is not None:
            self.method = to_native_string(self.method.upper())

    @staticmethod
    def _get_idna_encoded_host(host):
        import idna

        try:
            host = idna.encode(host, uts46=True).decode("utf-8")
        except idna.IDNAError:
            raise UnicodeError
        return host

    def prepare_url(self, url, params):
        """准备给定的HTTP URL。"""
        #: 接受具有字符串表示形式的对象。
        #: 我们无法盲目地调用 unicode/str 函数
        #: 因为这会在 python 3.x 上包含字节串指示器 (b'')。
        #: https://github.com/psf/requests/pull/2238
        if isinstance(url, bytes):
            url = url.decode("utf8")
        else:
            url = str(url)

        # 移除 url 前面的空白字符
        url = url.lstrip()

        # 不对非 HTTP 方案如 `mailto`、`data` 等进行 URL 准备，
        # 以避免 `url_parse` 的异常，它只处理 RFC 3986。
        if ":" in url and not url.lower().startswith("http"):
            self.url = url
            return

        # 支持 unicode 域名和路径。
        try:
            scheme, auth, host, port, path, query, fragment = parse_url(url)
        except LocationParseError as e:
            raise InvalidURL(*e.args)

        if not scheme:
            raise MissingSchema(
                f"无效的URL {url!r}: 没有提供方案。 "
                f"你可能是指 https://{url}?"
            )

        if not host:
            raise InvalidURL(f"无效的URL {url!r}: 没有提供主机")

        # 一般来说，我们想尝试对主机名进行 IDNA 编码，
        # 如果字符串包含非 ASCII 字符。这使用户能够自动获得正确的 IDNA 
        # 行为。对于只包含 ASCII 字符的字符串，我们需要验证它是否以通配符 (*) 开头，
        # 在允许未编码的主机名之前。
        if not unicode_is_ascii(host):
            try:
                host = self._get_idna_encoded_host(host)
            except UnicodeError:
                raise InvalidURL("URL的标签无效。")
        elif host.startswith(("*", ".")):
            raise InvalidURL("URL的标签无效。")

        # 小心地重建网络位置
        netloc = auth or ""
        if netloc:
            netloc += "@"
        netloc += host
        if port:
            netloc += f":{port}"

        # 裸域名不是有效的URL。
        if not path:
            path = "/"

        if isinstance(params, (str, bytes)):
            params = to_native_string(params)

        enc_params = self._encode_params(params)
        if enc_params:
            if query:
                query = f"{query}&{enc_params}"
            else:
                query = enc_params

        url = requote_uri(urlunparse([scheme, netloc, path, None, query, fragment]))
        self.url = url

    def prepare_headers(self, headers):
        """准备给定的HTTP头部。"""

        self.headers = CaseInsensitiveDict()
        if headers:
            for header in headers.items():
                # Raise exception on invalid header value.
                check_header_validity(header)
                name, value = header
                self.headers[to_native_string(name)] = value

    def prepare_body(self, data, files, json=None):
        """准备给定的HTTP体数据。"""

        # 检查是否是文件，fo，生成器，迭代器。
        # 如果不是，执行正常的过程。

        # 没有东西在你身上。
        body = None
        content_type = None

        if not data and json is not None:
            # urllib3要求body是bytes-like对象。Python 2的json.dumps
            # 就是这样提供的，但Python 3只提供Unicode字符串。
            content_type = "application/json"

            try:
                body = complexjson.dumps(json, allow_nan=False)
            except ValueError as ve:
                raise InvalidJSONError(ve, request=self)

            if not isinstance(body, bytes):
                body = body.encode("utf-8")

        is_stream = all(
            [
                hasattr(data, "__iter__"),
                not isinstance(data, (basestring, list, tuple, Mapping)),
            ]
        )

        if is_stream:
            try:
                length = super_len(data)
            except (TypeError, AttributeError, UnsupportedOperation):
                length = None

            body = data

            if getattr(body, "tell", None) is not None:
                # 在读取前记录当前文件位置。
                # 这将允许我们重定向时返回文件。
                try:
                    self._body_position = body.tell()
                except OSError:
                    # 这与None不同，允许我们在后面尝试重绕body时捕获失败的“tell”
                    self._body_position = object()

            if files:
                raise NotImplementedError(
                    "Streamed bodies and files are mutually exclusive."
                )

            if length:
                self.headers["Content-Length"] = builtin_str(length)
            else:
                self.headers["Transfer-Encoding"] = "chunked"
        else:
            # 多部分文件上传。
            if files:
                (body, content_type) = self._encode_files(files, data)
            else:
                if data:
                    body = self._encode_params(data)
                    if isinstance(data, basestring) or hasattr(data, "read"):
                        content_type = None
                    else:
                        content_type = "application/x-www-form-urlencoded"

            self.prepare_content_length(body)

            # 如果没有明确提供content-type，添加它。
            if content_type and ("content-type" not in self.headers):
                self.headers["Content-Type"] = content_type

        self.body = body

    def prepare_content_length(self, body):
        """根据请求方法和体准备Content-Length头部"""
        if body is not None:
            length = super_len(body)
            if length:
                # 如果长度存在，设置它。否则，我们fallback
                # 到Transfer-Encoding: chunked。
                self.headers["Content-Length"] = builtin_str(length)
        elif (
            self.method not in ("GET", "HEAD")
            and self.headers.get("Content-Length") is None
        ):
            # 对于可以有体但不提供体的方法，设置Content-Length为0
            # (i.e. not GET or HEAD)
            self.headers["Content-Length"] = "0"

    def prepare_auth(self, auth, url=""):
        """准备给定的HTTP auth数据。"""

        # 如果没有明确提供Auth，首先从URL中提取。
        if auth is None:
            url_auth = get_auth_from_url(self.url)
            auth = url_auth if any(url_auth) else None

        if auth:
            if isinstance(auth, tuple) and len(auth) == 2:
                # 特殊情况基本的HTTP auth
                auth = HTTPBasicAuth(*auth)

            # 允许auth做出其改变。
            r = auth(self)

            # 更新self以反映auth的改变。
            self.__dict__.update(r.__dict__)

            # 重新计算Content-Length
            self.prepare_content_length(self.body)

    def prepare_cookies(self, cookies):
        """准备给定的HTTP cookie数据。

        这个函数最终会使用cookielib从给定的cookies生成一个``Cookie``头部。由于cookielib的设计，如果头部已经存在，它将不会重新生成，意味着这个函数在** ``PreparedRequest <PreparedRequest>`` ** 对象的生命周期中只能被调用一次。任何后续对``prepare_cookies``的调用实际上都不会有任何效果，除非先前移除了"Cookie"头部。
        """
        if isinstance(cookies, cookielib.CookieJar):
            self._cookies = cookies
        else:
            self._cookies = cookiejar_from_dict(cookies)

        cookie_header = get_cookie_header(self._cookies, self)
        if cookie_header is not None:
            self.headers["Cookie"] = cookie_header

    def prepare_hooks(self, hooks):
        """准备给定的钩子。"""
        # 钩子可以被传递为None到prepare方法和这个
        # 方法。为了防止迭代None，如果钩子是False-y，只需使用一个空列表
        hooks = hooks or []
        for event in hooks:
            self.register_hook(event, hooks[event])


class Response:
    """
    :class:`Response <Response>` 对象，包含服务器对 HTTP 请求的响应。
    """

    __attrs__ = [
        "_content",
        "status_code",
        "headers",
        "url",
        "history",
        "encoding",
        "reason",
        "cookies",
        "elapsed",
        "request",
    ]

    def __init__(self):
        self._content = False
        self._content_consumed = False
        self._next = None

        #: 响应的 HTTP 状态的整数代码，例如 404 或 200。
        self.status_code = None

        #: 响应头的大小写不敏感的字典。
        #: 例如，``headers['content-encoding']`` 将返回
        #: ``'Content-Encoding'`` 响应头的值。
        self.headers = CaseInsensitiveDict()

        #: 响应的文件类型对象表示形式（用于高级用途）。
        #: 使用 ``raw`` 要求在请求上设置 ``stream=True``。
        #: 这个要求不适用于在 Requests 内部使用。
        self.raw = None

        #: 响应的最终 URL 位置。
        self.url = None

        #: 在访问 r.text 时使用的解码编码。
        self.encoding = None

        #: 来自请求历史的 :class:`Response <Response>` 对象列表。
        #: 任何重定向响应都会在这里结束。
        #: 该列表按照从最旧到最近的请求排序。
        self.history = []

        #: 例如"未找到"或"确认"的响应 HTTP 状态的文本原因。
        self.reason = None

        #: 服务器发送回来的 Cookies 的 CookieJar。
        self.cookies = cookiejar_from_dict({})

        #: 介于发送请求和响应到达之间的时间量（作为时间差）。
        #: 这个属性特别测量从发送请求的第一个字节到完成解析头的时间。
        #: 所以它不会受到消耗响应内容或
        #: ``stream`` 关键字参数的值的影响。
        self.elapsed = datetime.timedelta(0)

        #: 这是一个响应的 :class:`PreparedRequest <PreparedRequest>` 对象。
        self.request = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __getstate__(self):
        # 消耗所有内容；访问 content 属性确保
        # 内容已经完全读取。
        if not self._content_consumed:
            self.content

        return {attr: getattr(self, attr, None) for attr in self.__attrs__}

    def __setstate__(self, state):
        for name, value in state.items():
            setattr(self, name, value)
           
        # pickled 对象没有 .raw
        setattr(self, "_content_consumed", True)
        setattr(self, "raw", None)

    def __repr__(self):
        return f"<Response [{self.status_code}]>"

    def __bool__(self):
        """
        如果 :attr:`status_code` 小于 400，则返回 True。

        这个属性检查响应的状态码是否在 400 和 600 之间，
        以查看是否有客户端错误或服务器错误。如果状态码在 200 和 400 之间，
        这将返回 True。这不是检查响应代码是否为 ``200 OK`` 的检查。
        """
        return self.ok

    def __nonzero__(self):
        """
        如果 :attr:`status_code` 小于 400，则返回 True。

        这个属性检查响应的状态码是否在 400 和 600 之间，
        以查看是否有客户端错误或服务器错误。如果状态码在 200 和 400 之间，
        这将返回 True。这不是检查响应代码是否为 ``200 OK`` 的检查。
        """
        return self.ok 

    def __iter__(self):
        """允许您将响应用作迭代器。"""
        return self.iter_content(128) 

    @property
    def ok(self):
        """
        如果 :attr:`status_code` 小于 400，返回 True，否则返回 False。

        这个属性检查响应的状态码是否在 400 和 600 之间，
        以查看是否有客户端错误或服务器错误。如果状态码在 200 和 400 之间，
        这将返回 True。这**不**是检查响应代码是否为 ``200 OK`` 的检查。
        """
        try:
            self.raise_for_status()
        except HTTPError:
            return False
        return True

    @property
    def is_redirect(self):
        """如果此响应是格式良好的 HTTP 重定向，那么此响应可以被自动地处理
        （由 :meth:`Session.resolve_redirects` 完成）。则返回 True。
        """
        return "location" in self.headers and self.status_code in REDIRECT_STATI

    @property
    def is_permanent_redirect(self):
        """如果此响应是重定向的永久版本之一，则返回 True。"""
        return "location" in self.headers and self.status_code in (
            codes.moved_permanently,
            codes.permanent_redirect,
        )

    @property
    def next(self):
        """如果存在，返回重定向链中下一个请求的 PreparedRequest。"""
        return self._next

    @property
    def apparent_encoding(self):
        """由 charset_normalizer 或 chardet 库提供的明显编码。"""
        return chardet.detect(self.content)["encoding"]
        
    def iter_content(self, chunk_size=1, decode_unicode=False):
        """
        迭代响应数据。在请求上设置 stream=True 时，
        这可以避免一次性将大的响应读入内存。
        chunk_size 是应该读入内存的字节数。
        这并不一定是每个返回项的长度，因为可以进行解码。

        chunk_size 必须是 int 类型或 None。None 的值将根据 `stream` 的值
        有不同的功能。stream=True 将随着数据的到来以接收到的块大小读取数据。
        如果 stream=False，数据将以单个块返回。

        如果 decode_unicode 为 True，将使用基于响应的最佳可用编码解码内容。
        """

        def generate():
            # urllib3 的特殊情况。
            if hasattr(self.raw, "stream"):
                try:
                    yield from self.raw.stream(chunk_size, decode_content=True)
                except ProtocolError as e:
                    raise ChunkedEncodingError(e)
                except DecodeError as e:
                    raise ContentDecodingError(e)
                except ReadTimeoutError as e:
                    raise ConnectionError(e)
                except SSLError as e:
                    raise RequestsSSLError(e)
            else:
                # 标准文件类型对象。
                while True:
                    chunk = self.raw.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

            self._content_consumed = True

        if self._content_consumed and isinstance(self._content, bool):
            raise StreamConsumedError()
        elif chunk_size is not None and not isinstance(chunk_size, int):
            raise TypeError(
                f"chunk_size 必须是 int 类型，反而现在是 {type(chunk_size)} 类型。"
            )
        # 模拟读取内容的小块
        reused_chunks = iter_slices(self._content, chunk_size)

        stream_chunks = generate()

        chunks = reused_chunks if self._content_consumed else stream_chunks

        if decode_unicode:
            chunks = stream_decode_response_unicode(chunks, self)

        return chunks
    
    def iter_lines(
        self, chunk_size=ITER_CHUNK_SIZE, decode_unicode=False, delimiter=None
    ):
        """一次迭代响应数据的一行。当在请求上设置 stream=True 时，
        这可以避免一次性将大的响应读入内存。

        .. 注意:: 这个方法不是可重入安全的。
        """

        pending = None

        for chunk in self.iter_content(
            chunk_size=chunk_size, decode_unicode=decode_unicode
        ):
            if pending is not None:
                chunk = pending + chunk

            if delimiter:
                lines = chunk.split(delimiter)
            else:
                lines = chunk.splitlines()

            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            yield from lines

        if pending is not None:
            yield pending

    @property
    def content(self):
        """响应的内容，以字节为单位。"""

        if self._content is False:
            # 读取内容。
            if self._content_consumed:
                raise RuntimeError("这个响应的内容已经被消耗了")

            if self.status_code == 0 or self.raw is None:
                self._content = None
            else:
                self._content = b"".join(self.iter_content(CONTENT_CHUNK_SIZE)) or b""

        self._content_consumed = True
        # 不需要释放连接；这已经由 urllib3 处理，因为我们用尽了数据。
        return self._content
    
    @property
    def text(self):
        """
        内容的字符串形式（使用 :attr:`encoding` 进行解码）。

        如果可能，对响应的内容进行解码，如果它没有被解码过。
        首先，尝试使用给定的编码（如果有的话），否则尝试使用 apparent_encoding 属性进行解码。
        如果两者都失败，使用 UTF-8 进行解码。
        """

        content = None
        encoding = self.encoding

        # 尝试从内容中解码。
        if not self.content:
            return str("")

        # 尝试用 encoding（如果有）解码。
        if encoding is not None:
            try:
                content = str(self.content, encoding, errors='replace')
            except (LookupError, TypeError):
                pass

        # 尝试用 apparent_encoding（如果有）解码。
        if content is None:
            encoding = self.apparent_encoding

            try:
                content = str(self.content, encoding, errors='replace')
            except (LookupError, TypeError):
                pass

        # 尝试用 UTF-8 解码。
        if content is None:
            content = str(self.content, errors='replace')

        return content

    @property
    def json(self, **kwargs):
        """
        尝试以 json 方式解码响应（如果可能的话）。

        可选关键字参数params会传递给 json.loads()。

        :raises: simplejson.JSONDecodeError,如果响应的内容不能被解码为 JSON。
        """

        if not self.content:
            return None

        try:
            return complexjson.loads(
                self.content.decode(self.encoding), **kwargs
            )
        except UnicodeDecodeError:
            return complexjson.loads(self.content, **kwargs)
        
    @property
    def links(self):
        """返回响应的解析过的头部链接，如果有的话。"""

        header = self.headers.get("link")

        resolved_links = {}

        if header:
            links = parse_header_links(header)

            for link in links:
                key = link.get("rel") or link.get("url")
                resolved_links[key] = link

        return resolved_links

    def raise_for_status(self):
        """如果发生了:class:`HTTPError`，则抛出。"""

        http_error_msg = ""
        if isinstance(self.reason, bytes):
            # 我们首先尝试解码 utf-8 ，因为一些服务器
            # 选择本地化他们的原因字符串。如果字符串
            # 不是 utf-8，我们会回退到 iso-8859-1 处理所有其他
            # 编码。(参见 PR #3538)
            try:
                reason = self.reason.decode("utf-8")
            except UnicodeDecodeError:
                reason = self.reason.decode("iso-8859-1")
        else:
            reason = self.reason

        if 400 <= self.status_code < 500:
            http_error_msg = (
                f"{self.status_code} 客户端错误: {reason} 对应的 url: {self.url}"
            )

        elif 500 <= self.status_code < 600:
            http_error_msg = (
                f"{self.status_code} 服务器错误: {reason} 对应的 url: {self.url}"
            )

        if http_error_msg:
            raise HTTPError(http_error_msg, response=self)

    def close(self):
        """将连接返回到池中。一旦调用了这个方法，底层的 ``raw`` 对象就不能再被访问。

        *注：通常不需要显式调用此方法。*
        """
        if not self._content_consumed:
            self.raw.close()

        release_conn = getattr(self.raw, "release_conn", None)
        if release_conn is not None:
            release_conn()
