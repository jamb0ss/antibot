==========
antibot
==========

Analytics tool to identify bots in the web server logs.
Log must be converted to a CSV file before processing according to LOG_FORMAT.

Installation
------------

.. code:: shell

    $ pip install -U .

Usage
-----

.. code:: python

	$ python antibot.py traffic-log.csv --output=badbots.txt

