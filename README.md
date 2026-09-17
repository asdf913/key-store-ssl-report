# key-store-ssl-report

## Sample Command
<pre>java -jar keystore-ssl-report-0.0.1-SNAPSHOT.jar keyStore=/etc/ssl/certs/java/cacerts password=changeit url=https://mvnrepository.com</pre>

## Sample Output
<pre>File    =/etc/ssl/certs/java/cacerts
URL     =https://mvnrepository.com
KeyStore=mvnrepository.com 2026-12-05 19:22:43
HTTPS   =mvnrepository.com 2026-12-05 19:22:43</pre>

## Configuration file
<pre>java -jar keystore-ssl-report-0.0.1-SNAPSHOT.jar config=config.xml</pre>

## Config.xml

<pre>
&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;
&lt;config&gt;
  &lt;keyStore&gt;/etc/ssl/certs/java/cacerts&lt;/keyStore&gt;
  &lt;password&gt;changeit&lt;/password&gt;
  &lt;urls&gt;
    &lt;url&gt;https://mvnrepository.com&lt;/url&gt;
  &lt;/urls&gt;
&lt;/config&gt;
</pre>
