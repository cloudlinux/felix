# -*- coding: utf-8 -*-
# Copyright (c) 2016 Tigera, Inc. All rights reserved.
# Copyright (c) 2015 Cisco Systems.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
felix.fipmanager
~~~~~~~~~~~~~~~~

Actor that controls floating IP entries in the nat iptables table.
"""
import logging
import time
from calico.felix.frules import CHAIN_FIP_DNAT, CHAIN_FIP_SNAT
from calico.felix.actor import Actor, actor_message
from calico.felix.ipsets import Ipset, FELIX_PFX

_log = logging.getLogger(__name__)


class FloatingIPManager(Actor):
    def __init__(self, config, ip_version, iptables_updater):
        super(FloatingIPManager, self).__init__(qualifier="v%d" % ip_version)
        self.config = config
        self.ip_version = ip_version
        self.iptables_updater = iptables_updater
        self._dirty = False
        self._maps = dict()

    @actor_message()
    def apply_snapshot(self, nat_maps):
        """
        Replaces all NAT maps with the given snapshot.

        :param nat_maps: Dict of NAT maps.
        """

        _log.info("Applying floating IP NAT map snapshot.")
        self._maps = dict(nat_maps) # Make a copy.
        self._dirty = True

    @actor_message()
    def update_endpoint(self, endpoint_id, nat_maps):
        """
        Message sent to us by the WorkloadEndpoint to tell us we should add it
        to the NAT chain.

        Idempotent: does nothing if the mapping is already in the chain.

        :param nat_maps: Dict of NAT maps.
        """

        # Only add a cached entry for an endpoint that has fip data, this will
        # minimize the times we need to do a sync, since most endpoints will
        # likely not have any floating IPs.
        old_entry = self._maps.get(endpoint_id, None)
        if nat_maps and old_entry != nat_maps:
            self._maps[endpoint_id] = nat_maps
            self._dirty = True
        elif not nat_maps and old_entry:
            self._maps.pop(endpoint_id)
            self._dirty = True

    def _finish_msg_batch(self, _batch, _results):
        if self._dirty:
            _log.debug('Floating IP mappings have changed, refreshing.')
            self._reprogram_chains()
            self._dirty = False

    def _reprogram_chains(self):
        dnat = []
        snat = []
        reverse_maps = []
        all_ipam_pools = FELIX_PFX + "all-ipam-pools"
        # Since we don't use ordered dicts, sort to make sure each call with
        # the same data results in the same IP being used for the SNAT.
        for nat_maps in sorted(self._maps.values()):
            for nat_map in nat_maps:
                # Kuberdock fix: we don't want DNAT as soon as kube-proxy
                # manages public IP
                #dnat.append('--append %s -d %s -j DNAT --to-destination %s' %
                            #(CHAIN_FIP_DNAT, nat_map['ext_ip'],
                             #nat_map['int_ip']))
                if not nat_map['int_ip'] in reverse_maps:
                    # In order for an endpoint to be able to connect to its
                    # own floating IP, we have to do an SNAT.  Otherwise the
                    # endpoint would get a packet from outside itself claiming
                    # to be from itself, and generally drop it as invalid.
                    #
                    # If we do not take into account access control lists,
                    # really any IP that's not assigned to the endpoint should
                    # work for an SNAT address.  However, to try and make
                    # things be less confusing, we choose one of the floating
                    # IPs assigned to the endpoint.  If the endpoint has more
                    # than one floating IP assigned to it, then connections to
                    # floating IP #2 from the VM will end up having a source
                    # of floating IP #1 when they come back to the endpoint.
                    # In the general case, this should be fine as ACL
                    # processing happens before the SNAT translation.  It would
                    # technically be possible to always do a full source/dest
                    # swap by utilizing packet marking, but doing so would make
                    # the code much more complicated and create another
                    # iptables rule per floating IP.
                    snat.append('--append %s -s %s '
                                '-m set ! --match-set %s dst'
                                ' -j SNAT '
                                '--to-source %s' % (CHAIN_FIP_SNAT,
                                                    nat_map['int_ip'],
                                                    all_ipam_pools,
                                                    nat_map['ext_ip']))
                    reverse_maps.append(nat_map['int_ip'])

        if snat:
            # Kuberdock specific. We can create our snat rules only if
            # all_ipam_pools ipset already exists. In some cases it doesn't
            # exist at the moment when these rules are creating. So we wait
            # this ipset appearance (look at wait_for_ipset docstring for more
            # info).
            wait_for_ipset(all_ipam_pools)
        self.iptables_updater.rewrite_chains({CHAIN_FIP_DNAT: dnat,
                                              CHAIN_FIP_SNAT: snat}, {},
                                             async=True)


def wait_for_ipset(ipset_name):
    """Waits for a given ipset name exists in ipset list.
    Kuberdock specific.
    If it not exists after specified period of time (2 minutes now),
    then it will be created on our own risk.
    """
    ips = Ipset(ipset_name, '', 'inet', "hash:net")
    retry_count = 120
    retry_pause = 1
    for i in range(retry_count):
        if ips.exists():
            return
        _log.info(
            "KUBERDOCK: wait_for_ipset(%s) check failed, retry count: %s",
            ipset_name, i
        )
        time.sleep(retry_pause)
    _log.info("KUBERDOCK: Force create of ipset '%s'", ipset_name)
    ips.ensure_exists()
