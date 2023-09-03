"""
requests.api
~~~~~~~~~~~~

该模块实现了 Requests API。

:copyright: (c) 2012 by Kenneth Reitz.
:license: Apache2, see LICENSE for more details.
"""

from . import sessions

def request(method, url, **kwargs):
    """构建并发送一个 :class:`Request <Request>`。

    :param method: 新的 :class:`Request` 对象的方法: ``GET``, ``OPTIONS``, ``HEAD``, ``POST``, ``PUT``, ``PATCH``, 或 ``DELETE``。
    :param url: 新的 :class:`Request` 对象的URL。
    :param params: （可选）字典，元组的列表或字节，用于在 :class:`Request` 的查询字符串中发送。
    :param data: （可选）字典，元组的列表，字节，或文件类
        对象，用于在 :class:`Request` 的正文中发送。
    :param json: （可选）一个可以序列化为JSON的Python对象，用于在 :class:`Request` 的正文中发送。
    :param headers: （可选）要与 :class:`Request` 一起发送的HTTP头的字典。
    :param cookies: （可选）要与 :class:`Request` 一起发送的字典或CookieJar对象。
    :param files: （可选）用于多部分编码上传的 ``'name': file-like-objects`` （或 ``{'name': file-tuple}``）的字典。
        ``file-tuple`` 可以是一个 2-tuple ``('filename', fileobj)``, 3-tuple ``('filename', fileobj, 'content_type')``
        或一个 4-tuple ``('filename', fileobj, 'content_type', custom_headers)``, 其中 ``'content_type'`` 是一个字符串
        定义给定文件的内容类型，而 ``custom_headers`` 是一个包含要为文件添加的额外头的类似字典的对象。
    :param auth: （可选）Auth tuple，用于启用基本/摘要/自定义HTTP Auth。
    :param timeout: （可选）在放弃之前，等待服务器发送数据的秒数，
        作为一个浮点数，或者一个 :ref:`(connect timeout, read
        timeout) <timeouts>` tuple。
    :type timeout: float or tuple
    :param allow_redirects: （可选）布尔值。启用/禁用 GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD 重定向。默认为 ``True``。
    :type allow_redirects: bool
    :param proxies: （可选）将协议映射到代理URL的字典。
    :param verify: （可选）可以是一个布尔值，在这种情况下，它控制我们是否验证
            服务器的TLS证书，或者一个字符串，在这种情况下，它必须是一个路径
            到要使用的CA bundle。默认为 ``True``。
    :param stream: （可选）如果 ``False``，响应内容将被立即下载。
    :param cert: （可选）如果是字符串，表示ssl client cert文件（.pem）的路径。如果是元组，表示 ('cert', 'key') pair。
    :return: :class:`Response <Response>` 对象
    :rtype: requests.Response

    使用方法::

      >>> import requests
      >>> req = requests.request('GET', 'https://httpbin.org/get')
      >>> req
      <Response [200]>
    """

    # By using the 'with' statement we are sure the session is closed, thus we
    # avoid leaving sockets open which can trigger a ResourceWarning in some
    # cases, and look like a memory leak in others.
    with sessions.Session() as session:
        return session.request(method=method, url=url, **kwargs)


def get(url, params=None, **kwargs):
    r"""发送一个 GET 请求。

    :param url: 新的 :class:`Request` 对象的URL。
    :param params: （可选）字典，元组的列表或字节，用于在 :class:`Request` 的查询字符串中发送。
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` 对象
    :rtype: requests.Response
    """

    return request("get", url, params=params, **kwargs)


def options(url, **kwargs):
    r"""发送一个 OPTIONS 请求。

    :param url: 新的 :class:`Request` 对象的URL。
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` 对象
    :rtype: requests.Response
    """

    return request("options", url, **kwargs)


def head(url, **kwargs):
    r"""发送一个 HEAD 请求。

    :param url: 新的 :class:`Request` 对象的URL。
    :param \*\*kwargs: Optional arguments that ``request`` takes. If
        `allow_redirects` is not provided, it will be set to `False` (as
        opposed to the default :meth:`request` behavior).
    :return: :class:`Response <Response>` 对象
    :rtype: requests.Response
    """

    kwargs.setdefault("allow_redirects", False)
    return request("head", url, **kwargs)


def post(url, data=None, json=None, **kwargs):
    r"""发送一个 POST 请求。

    :param url: 新的 :class:`Request` 对象的URL。
    :param data: （可选）字典，元组的列表，字节，或文件类
        对象，用于在 :class:`Request` 的正文中发送。
    :param json: （可选）一个可以序列化为JSON的Python对象，用于在 :class:`Request` 的正文中发送。
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` 对象
    :rtype: requests.Response
    """

    return request("post", url, data=data, json=json, **kwargs)


def put(url, data=None, **kwargs):
    r"""发送一个 PUT 请求。

    :param url: 新的 :class:`Request` 对象的URL。
    :param data: （可选）字典，元组的列表，字节，或文件类
        对象，用于在 :class:`Request` 的正文中发送。
    :param json: （可选）一个可以序列化为JSON的Python对象，用于在 :class:`Request` 的正文中发送。
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` 对象
    :rtype: requests.Response
    """

    return request("put", url, data=data, **kwargs)


def patch(url, data=None, **kwargs):
    r"""发送一个 PATCH 请求。

    :param url: 新的 :class:`Request` 对象的URL。
    :param data: （可选）字典，元组的列表，字节，或文件类
        对象，用于在 :class:`Request` 的正文中发送。
    :param json: （可选）一个可以序列化为JSON的Python对象，用于在 :class:`Request` 的正文中发送。
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` 对象
    :rtype: requests.Response
    """

    return request("patch", url, data=data, **kwargs)


def delete(url, **kwargs):
    r"""发送一个 DELETE 请求。

    :param url: 新的 :class:`Request` 对象的URL。
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` 对象
    :rtype: requests.Response
    """

    return request("delete", url, **kwargs)