# Item-catalog

   I have developed an application that provides a list of Menu items within a variety of Restaurants as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.
How to develop a RESTful web application using the Python framework Flask along with implementing third-party OAuth authentication.

# Setup: 
   1. Install Vagrant and virtual box
      * vagrantup.com and virtualbox.org
   2. Launch the Vagrant VM 
      * vargrant up
   3. Login to your vagrant environment 
       * $vagrant ssh
 
# How to run your project
   1. vagrant@vagrant-ubuntu-trusty-32:~$ cd /vagrant/project4FullstackFound
   
   2. vagrant@vagrant-ubuntu-trusty-32:/vagrant/project4FullstackFound$ python finalproject.py

 Access and test my application by visiting http://localhost:5000 locally
   
# How to Create Database 

   To initialize the SQLite database (create empty tables)
   ##Database name is restaurantmenuwithusers.db
   
   1. vagrant@vagrant-ubuntu-trusty-32:~$ cd /vagrant/project4FullstackFound
   
   2. vagrant@vagrant-ubuntu-trusty-32:/vagrant/project4FullstackFound$ python database_setup.py
   
# Populate/load information on tables.
(Udacity already created this lotofmenu.py)
   
   1. vagrant@vagrant-ubuntu-trusty-32:/vagrant/project4FullstackFound$ python lotofmenu.py
      
      
