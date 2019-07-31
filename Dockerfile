FROM ubuntu:16.04

ENV NGINX_VERSION=1.17.2
ENV LUAROCKS_VERSION=2.4.4

RUN apt-get update && apt-get -y install \
                build-essential \
                autoconf \
                automake \
                binutils \
                ca-certificates \
                cmake \
                curl \
                gcc \
                libgd-dev \
                libgeoip-dev \
				libperl-dev \
                git \
                gnupg \
                gnupg \
                libc-dev \
                libtool \
                libxslt-dev \
                make \
                libpcre3-dev \
                tar \
                tzdata \
                libunwind-dev \
                software-properties-common \
				unzip wget \
                && add-apt-repository ppa:longsleep/golang-backports && apt-get update && apt-get -y install golang-go


RUN (git clone --depth=1 https://boringssl.googlesource.com/boringssl /usr/src/boringssl \
                && sed -i 's@out \([>=]\) TLS1_2_VERSION@out \1 TLS1_3_VERSION@' /usr/src/boringssl/ssl/ssl_lib.cc \
                && sed -i 's@ssl->version[ ]*=[ ]*TLS1_2_VERSION@ssl->version = TLS1_3_VERSION@' /usr/src/boringssl/ssl/s3_lib.cc \
                && sed -i 's@(SSL3_VERSION, TLS1_2_VERSION@(SSL3_VERSION, TLS1_3_VERSION@' /usr/src/boringssl/ssl/ssl_test.cc \
                && sed -i 's@\$shaext[ ]*=[ ]*0;@\$shaext = 1;@' /usr/src/boringssl/crypto/*/asm/*.pl \
                && sed -i 's@\$avx[ ]*=[ ]*[0|1];@\$avx = 2;@' /usr/src/boringssl/crypto/*/asm/*.pl \
                && sed -i 's@\$addx[ ]*=[ ]*0;@\$addx = 1;@' /usr/src/boringssl/crypto/*/asm/*.pl \
                && mkdir -p /usr/src/boringssl/build /usr/src/boringssl/.openssl/lib /usr/src/boringssl/.openssl/include \
                && ln -sf /usr/src/boringssl/include/openssl /usr/src/boringssl/.openssl/include/openssl \
                && touch /usr/src/boringssl/.openssl/include/openssl/ssl.h \
                && cmake -B/usr/src/boringssl/build -H/usr/src/boringssl \
                && make -C/usr/src/boringssl/build -j$(getconf _NPROCESSORS_ONLN) \
                && cp /usr/src/boringssl/build/crypto/libcrypto.a /usr/src/boringssl/build/ssl/libssl.a /usr/src/boringssl/.openssl/lib) 


RUN cd /usr/src/ && git clone https://github.com/openresty/luajit2.git && cd luajit2 && make && make install && ldconfig
RUN (git clone --depth=1 https://github.com/nginx-modules/libbrotli /usr/src/libbrotli \
		&& cd /usr/src/libbrotli \
		&& ./autogen.sh && ./configure && make -j$(getconf _NPROCESSORS_ONLN) && make install && ldconfig) \
	&& git clone --depth=1 --recurse-submodules https://github.com/google/ngx_brotli /usr/src/ngx_brotli
RUN cd /usr/src/ && git clone --depth=1 https://github.com/openresty/headers-more-nginx-module /usr/src/ngx_headers_more
RUN cd /usr/src/ && git clone https://github.com/simplresty/ngx_devel_kit.git
RUN cd /usr/src/ && git clone --depth=1 https://github.com/openresty/lua-nginx-module.git /usr/src/lua-nginx-module
RUN cd /usr/src/ && wget http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz -O nginx.tar.gz && tar -zxf nginx.tar.gz && rm -fr nginx.tar.gz && mv nginx-$NGINX_VERSION nginx
RUN cd  /usr/src/nginx/ \ 
	&&  LUAJIT_INC=/usr/local/include/luajit-2.1 \ 
	LUAJIT_LIB=/usr/local/lib \ 
	./configure \ 
	--prefix=/etc/nginx \ 
	--sbin-path=/usr/sbin/nginx \ 
	--modules-path=/usr/lib/nginx/modules \ 
	--conf-path=/etc/nginx/nginx.conf \ 
	--error-log-path=/var/log/nginx/error.log \ 
	--http-log-path=/var/log/nginx/access.log \ 
	--pid-path=/var/run/nginx.pid \ 
	--lock-path=/var/run/nginx.lock \ 
	--http-client-body-temp-path=/var/cache/nginx/client_temp \ 
	--http-proxy-temp-path=/var/cache/nginx/proxy_temp \ 
	--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \ 
	--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \ 
	--http-scgi-temp-path=/var/cache/nginx/scgi_temp \ 
	--user=nginx \ 
	--group=nginx \ 
	--with-http_ssl_module \ 
	--with-http_realip_module \ 
	--with-http_addition_module \ 
	--with-http_sub_module \ 
	--with-http_dav_module \ 
	--with-http_flv_module \ 
	--with-http_mp4_module \ 
	--with-http_gunzip_module \ 
	--with-http_gzip_static_module \ 
	--with-http_random_index_module \ 
	--with-http_secure_link_module \ 
	--with-http_stub_status_module \ 
	--with-http_auth_request_module \ 
	--with-http_xslt_module=dynamic \ 
	--with-http_image_filter_module=dynamic \ 
	--with-http_geoip_module=dynamic \ 
	--with-http_perl_module=dynamic \ 
	--with-threads \ 
	--with-stream \ 
	--with-stream_ssl_module \ 
	--with-stream_ssl_preread_module \ 
	--with-stream_realip_module \ 
	--with-stream_geoip_module=dynamic \ 
	--with-http_slice_module \ 
	--with-mail \ 
	--with-mail_ssl_module \ 
	--with-compat \ 
	--with-file-aio \ 
	--with-http_v2_module \
	--with-stream \
	--with-stream_ssl_module \
	--with-stream_ssl_preread_module \
	--with-stream_realip_module \
	--with-cc-opt=-I/usr/src/boringssl/.openssl/include \ 
	--with-ld-opt=-L/usr/src/boringssl/.openssl/lib \ 
	--with-ld-opt="-Wl,-rpath,/usr/local/include/luajit-2.1" \ 
	--add-dynamic-module=/usr/src/ngx_headers_more \ 
	--with-cc-opt=-I/usr/src/boringssl/.openssl/include \ 
	--with-ld-opt="-L/usr/src/boringssl/.openssl/lib -L/usr/local/lib/" \
	--add-module=/usr/src/ngx_devel_kit \ 
	--add-module=/usr/src/lua-nginx-module \
	--add-module=/usr/src/ngx_brotli
RUN cd /usr/src/nginx && make -j$(getconf _NPROCESSORS_ONLN) && make install


RUN wget https://luarocks.org/releases/luarocks-${LUAROCKS_VERSION}.tar.gz -O /usr/src/luarocks-${LUAROCKS_VERSION}.tar.gz \
    && cd /usr/src/ && tar zxpf luarocks-${LUAROCKS_VERSION}.tar.gz \
    && ln -s /usr/local/bin/luajit /usr/local/bin/lua \
    && cd /usr/src/luarocks-${LUAROCKS_VERSION} && ./configure --prefix=/usr/local --with-lua=/usr/local --with-lua-include=/usr/local/include/luajit-2.1/ \
    && cd /usr/src/luarocks-${LUAROCKS_VERSION} && make build && make install \
    && chmod a+r /usr/local/share/lua/5.1

RUN cd /usr/src && git clone  https://github.com/openresty/lua-resty-core.git \
	&& cd lua-resty-core \
	&& make install

RUN cd /usr/src && git clone  https://github.com/openresty/lua-resty-lrucache.git \
	&& cd lua-resty-lrucache \
	&& make install


RUN USER=root HOME=/root /usr/local/bin/luarocks install lua-resty-jwt \
    && USER=root HOME=/root /usr/local/bin/luarocks install lua-resty-cookie \
	&& USER=root HOME=/root /usr/local/bin/luarocks install redis-lua \
	&& USER=root HOME=/root /usr/local/bin/luarocks install json-lua \
	&& USER=root HOME=/root /usr/local/bin/luarocks install lua-cjson


RUN groupadd --system nginx \
	&& useradd  --system -d /var/cache/nginx --shell=/sbin/nologin -g nginx nginx \
	&& mkdir -p /var/cache/nginx && chown -R nginx:nginx /var/cache/nginx

ADD nginx.conf /etc/nginx/nginx.conf


RUN (mkdir /root/nginx-${NGINX_VERSION} \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/DEBIAN \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/etc \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/usr/lib \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/usr/sbin \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/var/cache/nginx \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/var/log/nginx \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/usr/local/lib/ \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/usr/local/bin/ \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/usr/local/include/ \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/usr/local/share/ \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/usr/local/lib/pkgconfig \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/root/.cache/luarocks \
	&& mkdir -p /root/nginx-${NGINX_VERSION}/lib/systemd/system/ \
	&& cp -R /etc/nginx /root/nginx-${NGINX_VERSION}/etc/nginx \
	&& cp -R /usr/lib/nginx /root/nginx-${NGINX_VERSION}/usr/lib/nginx \
	&& cp /usr/sbin/nginx /root/nginx-${NGINX_VERSION}/usr/sbin/nginx \
	&& cp -d -R /usr/local/lib/* /root/nginx-${NGINX_VERSION}/usr/local/lib/ \
	&& ls -l1ah /usr/local/lib/ \
	&& cp -R /usr/local/etc/luarocks /root/nginx-${NGINX_VERSION}/etc/ \
	&& cp -R /usr/local/include/luajit-2.1 /root/nginx-${NGINX_VERSION}/usr/local/include/ \
	&& cp /usr/local/lib/pkgconfig/luajit.pc /root/nginx-${NGINX_VERSION}/usr/local/lib/pkgconfig \
	&& cp -R /usr/local/share/lua* /root/nginx-${NGINX_VERSION}/usr/local/share/ \
	&& cp -d /usr/local/bin/* /root/nginx-${NGINX_VERSION}/usr/local/bin/ \
	)
ADD control /root/nginx-${NGINX_VERSION}/DEBIAN/
ADD rules /root/nginx-${NGINX_VERSION}/DEBIAN/
ADD postinst /root/nginx-${NGINX_VERSION}/DEBIAN/
ADD postrm /root/nginx-${NGINX_VERSION}/DEBIAN/
ADD nginx.service /root/nginx-${NGINX_VERSION}/lib/systemd/system/
RUN chmod 0775 /root/nginx-${NGINX_VERSION}/DEBIAN/postinst
RUN chmod 0775 /root/nginx-${NGINX_VERSION}/DEBIAN/postrm


RUN (cd /root/ \
	&&	dpkg-deb --build nginx-${NGINX_VERSION} \
	)

