// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package builtin

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/snap"
)

const msgQSummary = `allows Posix message queue with a specific name`

const msgQBaseDeclarationSlots = `
  msg-queue:
    allow-installation:
      slot-snap-type:
        - app
        - gadget
    deny-connection:
      slot-attributes:
        name: .+
    allow-auto-connection:
      plug-attributes:
        name: $SLOT(name)
`

const msgQSecComp = `
# Description: Allow owning a name and send/receive msg over posix message queue
mq_getsetattr
mq_notify
mq_open
mq_timedreceive
mq_timedreceive_time64
mq_timedsend
mq_timedsend_time64
mq_unlink
`

type msgQInterface struct{}

func (iface *msgQInterface) Name() string {
	return "msg-queue"
}

func (iface *msgQInterface) StaticInfo() interfaces.StaticInfo {
	return interfaces.StaticInfo{
		Summary:              msgQSummary,
		BaseDeclarationSlots: msgQBaseDeclarationSlots,
	}
}

// Obtain yaml-specified queue name
func (iface *msgQInterface) getAttribs(attribs interfaces.Attrer) (string, error) {
	// name attribute
	var name string
	if err := attribs.Attr("name", &name); err != nil {
		return "", fmt.Errorf("cannot find attribute 'name'")
	}
	return name, nil
}

func (iface *msgQInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	name, err := iface.getAttribs(plug)
	if err != nil {
		return err
	}

	nameSlot, err := iface.getAttribs(slot)
	if err != nil {
		return err
	}

	// ensure that we only connect to slot with matching attributes
	if name != nameSlot {
		return nil
	}
	msgQSnippet := bytes.NewBuffer(nil)
	fmt.Fprintf(msgQSnippet, "%s rw,\n", name)

	spec.AddSnippet(msgQSnippet.String())
	return nil
}

func (iface *msgQInterface) AppArmorPermanentSlot(spec *apparmor.Specification, slot *snap.SlotInfo) error {
	msgQSnippet := bytes.NewBuffer(nil)
	name, err := iface.getAttribs(slot)
	if err != nil {
		return err
	}
	fmt.Fprintf(msgQSnippet, "%s rw,\n", name)

	spec.AddSnippet(msgQSnippet.String())
	return nil
}

func (iface *msgQInterface) SecCompPermanentSlot(spec *seccomp.Specification, slot *snap.SlotInfo) error {
	spec.AddSnippet(msgQSecComp)
	return nil
}

func (iface *msgQInterface) SecCompConnectedPlug(spec *seccomp.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	spec.AddSnippet(msgQSecComp)
	return nil
}

func (iface *msgQInterface) AppArmorConnectedSlot(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	//Functionality implemented in AppArmorPermanentSlot
	return nil
}

func (iface *msgQInterface) BeforePreparePlug(plug *snap.PlugInfo) error {
	name, err := iface.getAttribs(plug)
	if strings.Contains(name, "/") != true {
		return fmt.Errorf(`msg queue name should start with /`)
	}
	if len(name) < 2 {
		return fmt.Errorf(`Invalid length for msg-queue name`)
	}
	return err
}

func (iface *msgQInterface) BeforePrepareSlot(slot *snap.SlotInfo) error {
	name, err := iface.getAttribs(slot)
	if strings.Contains(name, "/") != true {
		return fmt.Errorf(`msg queue name should start with /`)
	}
	if len(name) < 2 {
		return fmt.Errorf(`Invalid length for msg-queue name`)
	}
	return err
}

func (iface *msgQInterface) AutoConnect(*snap.PlugInfo, *snap.SlotInfo) bool {
	// allow what declarations allowed
	return true
}

func init() {
	registerIface(&msgQInterface{})
}
