rm -rf plugin
mkdir plugin
mkdir plugin/open_rcc
cp -R ebin include priv plugin/open_rcc

echo "***************************************************************"
echo "* Compile success!                                            *"
echo "*                                                             *"
echo "* There is a new directory inside this one called 'plugin'.   *"
echo "* Put the contents of that directory in your OpenACD's plugin *"
echo "* directory.  Next, in the OpenACD shell, invoke:             *"
echo "*     cpx:reload_plugins().                                   *"
echo "***************************************************************"
