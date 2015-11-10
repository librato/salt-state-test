# Overview
## Why this exists

As with any programming language, there is a good chance that when
editing a salt state, you have made a mistake.

In order to detect these mistakes, the salt engine needs to read your
state, and apply it with the grains and pillars appropriate for the
minion you are targeting.

Salt makes it very easy to test with an active master (or similar
situations such as a masterless setup, or salt-ssh) by putting the state
on the master (or similar) and calling the test_state, e.g.:

```
root@saltmaster# salt test-minion state.show_sls test_state
```

This will display the state when it renders.  However, the cost of this
is longer than what's ideal.

In order to provide a slightly faster unit testing cycle, as well as a
pre-commit hook that can be used to prevent unintended errors from
getting into git, this script can do much of the same compilation as a salt
master and the state.show\_sls state (this uses the show\_sls state).

## How I'm thinking about this

The primary differences are as follows:

1. All configuration is contained within the script and its configuration.
1. Grain data is not discovered from minions, it's provided in configuration.
1. Pillar data is provided as a json file rather than data collected by the saltmaster.

For each state that is being tested, a pseudo-run is initiated.  It
gathers its data from the grain configuration, pillar configuration, and
internal values (most of which are default values internal to salt).

Once that data is obtained, the pseudo-run is executed and the
state.show\_sls function is used to return the data structure that is
the result of the state being rendered.

To test a hypothesis, it's important to have an hypothesis in the first
place.  The results of the pseudo-run are compared with the desired
results.  Any differences present in the relevent keys cause the run in
general to fail (this is to support acting as a git hook, so that a
broken state isn't committed).

When the test script is invoked without any flags, only keys that exist
in the desired result are compared to the actual result.  This makes it
easy to get started, because you can start with no expectations and add
expecetations as you go along.

However, the "-t" flag can be passed to the script in order to "test all"

# How to get started

Dependencies are in the requirements.txt file.

## Setting up tests for your state files.

The primary function of the unit test confirms whether a salt state can
render.  After it renders, it can proceed with its second function which
is confirming that the output of the state being rendered matches the
desired output: does the test work?

## The test directory 

This expects a git repo to be setup up for your salt states, as follows:

```
<some repo name>
 +-test
 | |-test_salt_state.py
 | |-config.json
 | |-grains.json
 +-states
   +-state1
     |-init.sls
     |-install.sls
     |-uninstall.sls
     +-test
       |-pillar.json
       |-init.json
       |-install.json
       |-uninstall.json
```

### test\_salt\_state.py

The test script.  The name shouldn't be too important.

### The config.json file

The config.json file currently only requires the key "states_dir" and
the value "states/" to tell the test script where to find its states
relative to the root of the git repo.  The "/" at the end of states is
important don't forget it.  In the example above, this would be :

```
{
 "states_dir" : "states/"
}
```

### The global grains file

There is a grains.json file in this directory that will be used to 
simulate a system.

### The state to be tested

Each state should have its own directory.  
#### The per-state test directory and its contents

#### The pillar file

In the ```<statename>/test``` directory there will be a file called
pillar.json.  This will be read and used as the pillars for all of the
states that are tested in this, the ```<statename>``` state.

#### The expected results files

For each state, an expected results file is created as a json documented
that contains the values to be tested with.

So, if you're testing the state called state1.init, it's defined in the
file state1/init.sls.  When the test is run, it will apply the grains
from the top-level test/grains.json, and the pillar values that are
provided in the state1/test/pillar.json file, and those are provided to
the state1.init state and compare the output the data in the json
document state1/test/init.json.  

The test will fail if there are differences between the keys that will
be tested, and the output.

To create an expected result file, the test script can be invoked with
the ```-j``` flag as follows:

```
$ python test/test_salt_state.py -j  states/state1/init.sls \
  > states/state1/test/init.json
```

### Testing more thoroughly

To see the complete set of adds and deletes, not just those that are in
the expected results files, you can pass in the ```-t``` flag to the test

