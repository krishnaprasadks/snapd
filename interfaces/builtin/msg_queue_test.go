// -*- Mode: Go; indent-tabs-mode: t -*-

/*
*
*
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

package builtin_test

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/testutil"
)

type MsgQInterfaceSuite struct {
	testutil.BaseTest
	iface interfaces.Interface

	snapInfo     *snap.Info
	msgQPlugInfo *snap.PlugInfo
	msgQPlug     *interfaces.ConnectedPlug
	//Includes plug info with message queue name defined in regex to allow list of message queues
	msgQRegexPlugInfo *snap.PlugInfo
	msgQRegexPlug     *interfaces.ConnectedPlug

	msgQSlotInfo *snap.SlotInfo
	msgQSlot     *interfaces.ConnectedSlot
	//Includes plug info with message queue name defined in regex to allow list of message queues
	msgQRegexSlotInfo *snap.SlotInfo
	msgQRegexSlot     *interfaces.ConnectedSlot
}

var _ = Suite(&MsgQInterfaceSuite{
	iface: builtin.MustInterface("msg-queue"),
})

func (s *MsgQInterfaceSuite) SetUpSuite(c *C) {
	s.snapInfo = snaptest.MockInfo(c, `
name: test-msgq
version: 0
slots:
  test-msgq-slot:
    interface: msg-queue
    name: /sp-server
  test-msgq-regex-slot:
    interface: msg-queue
    name: /sp*-cl*-*
plugs:
  test-msgq-plug:
    interface: msg-queue
    name: /sp-server
  test-msgq-regex-plug:
    interface: msg-queue
    name: /sp*-cl*-*

apps:
  test-msgq-provider:
    slots:
      - test-msgq-slot
      - test-msgq-regex-slot
  test-msgq-consumer:
     plugs:
       - test-msgq-plug
       - test-msgq-regex-plug
`, nil)
}

func (s *MsgQInterfaceSuite) SetUpTest(c *C) {
	s.msgQSlotInfo = s.snapInfo.Slots["test-msgq-slot"]
	s.msgQSlot = interfaces.NewConnectedSlot(s.msgQSlotInfo, nil, nil)
	s.msgQRegexSlotInfo = s.snapInfo.Slots["test-msgq-regex-slot"]
	s.msgQRegexSlot = interfaces.NewConnectedSlot(s.msgQRegexSlotInfo, nil, nil)

	s.msgQPlugInfo = s.snapInfo.Plugs["test-msgq-plug"]
	s.msgQPlug = interfaces.NewConnectedPlug(s.msgQPlugInfo, nil, nil)
	s.msgQRegexPlugInfo = s.snapInfo.Plugs["test-msgq-regex-plug"]
	s.msgQRegexPlug = interfaces.NewConnectedPlug(s.msgQRegexPlugInfo, nil, nil)
}

func (s *MsgQInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "msg-queue")
}

func (s *MsgQInterfaceSuite) TestSanitizeSlotQueue(c *C) {
	var mockSnapYaml = `name: msgq-snap
version: 1.0
slots:
  msgq-slot:
    interface: msg-queue
    name: /sp-client
`

	info := snaptest.MockInfo(c, mockSnapYaml, nil)

	slot := info.Slots["msgq-slot"]
	c.Assert(interfaces.BeforePrepareSlot(s.iface, slot), IsNil)
}

func (s *MsgQInterfaceSuite) TestSanitizePlugQueue(c *C) {
	var mockSnapYaml = `name: msgq-snap
version: 1.0
plugs:
  msgq-plug:
    interface: msg-queue
    name: /sp-client
`

	info := snaptest.MockInfo(c, mockSnapYaml, nil)

	plug := info.Plugs["msgq-plug"]
	c.Assert(interfaces.BeforePreparePlug(s.iface, plug), IsNil)
}

func (s *MsgQInterfaceSuite) TestPermanentSlotSecComp(c *C) {
	seccompSpec := &seccomp.Specification{}
	err := seccompSpec.AddPermanentSlot(s.iface, s.msgQSlotInfo)
	c.Assert(err, IsNil)
	c.Assert(seccompSpec.SecurityTags(), DeepEquals, []string{"snap.test-msgq.test-msgq-provider"})
	snippet := seccompSpec.SnippetForTag("snap.test-msgq.test-msgq-provider")
	c.Check(snippet, testutil.Contains, "mq_getsetattr\nmq_notify\nmq_open\nmq_timedreceive\nmq_timedreceive_time64\nmq_timedsend\nmq_timedsend_time64\nmq_unlink\n")
}

func (s *MsgQInterfaceSuite) TestConnectedPlugSecComp(c *C) {
	seccompSpec := &seccomp.Specification{}
	err := seccompSpec.AddConnectedPlug(s.iface, s.msgQPlug, s.msgQSlot)
	c.Assert(err, IsNil)
	c.Assert(seccompSpec.SecurityTags(), DeepEquals, []string{"snap.test-msgq.test-msgq-consumer"})
	snippet := seccompSpec.SnippetForTag("snap.test-msgq.test-msgq-consumer")
	c.Check(snippet, testutil.Contains, "mq_getsetattr\nmq_notify\nmq_open\nmq_timedreceive\nmq_timedreceive_time64\nmq_timedsend\nmq_timedsend_time64\nmq_unlink\n")
}

func (s *MsgQInterfaceSuite) TestPermanentSlotAppArmor(c *C) {
	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddPermanentSlot(s.iface, s.msgQSlotInfo)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.test-msgq.test-msgq-provider"})
	c.Assert(apparmorSpec.SnippetForTag("snap.test-msgq.test-msgq-provider"), DeepEquals, "/sp-server rw,\n")
}

func (s *MsgQInterfaceSuite) TestConnectedPlugAppArmor(c *C) {
	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, s.msgQPlug, s.msgQSlot)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.test-msgq.test-msgq-consumer"})
	c.Assert(apparmorSpec.SnippetForTag("snap.test-msgq.test-msgq-consumer"), DeepEquals, "/sp-server rw,\n")
}

//Test case to check whether interface allows list of message queues(queue names) using Regular expression
//Eg: sp1-cl1-tx, sp2-cl2-rx etc.
func (s *MsgQInterfaceSuite) TestPermanentSlotAppArmorWithRegexMsgQ(c *C) {
	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddPermanentSlot(s.iface, s.msgQRegexSlotInfo)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.test-msgq.test-msgq-provider"})
	c.Assert(apparmorSpec.SnippetForTag("snap.test-msgq.test-msgq-provider"), DeepEquals, "/sp*-cl*-* rw,\n")
}

//Test case to check whether interface allows list of message queues(queue names) using Regular expression
//Eg: sp1-cl1-tx, sp2-cl2-rx etc.
func (s *MsgQInterfaceSuite) TestConnectedPlugAppArmorWithRegexMsgQ(c *C) {
	apparmorSpec := &apparmor.Specification{}
	err := apparmorSpec.AddConnectedPlug(s.iface, s.msgQRegexPlug, s.msgQRegexSlot)
	c.Assert(err, IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.test-msgq.test-msgq-consumer"})
	c.Assert(apparmorSpec.SnippetForTag("snap.test-msgq.test-msgq-consumer"), DeepEquals, "/sp*-cl*-* rw,\n")
}

func (s *MsgQInterfaceSuite) TestStaticInfo(c *C) {
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "msg-queue")
}

func (s *MsgQInterfaceSuite) TestAutoConnect(c *C) {
	c.Assert(s.iface.AutoConnect(s.msgQPlugInfo, s.msgQSlotInfo), Equals, true)
	c.Assert(s.iface.AutoConnect(s.msgQRegexPlugInfo, s.msgQRegexSlotInfo), Equals, true)
}

func (s *MsgQInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
