(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2012, Cedric Cellier
 *
 * This file is part of RobiNet.
 *
 * RobiNet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RobiNet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with RobiNet.  If not, see <http://www.gnu.org/licenses/>.
 *)
(**
  Recursive types describing simulations, widget, power sources etc
 *)
open Clock

(** {2 Locations}
 *
 * Widgets can have a location where the UI will draw them on the map.
 * Also used to compute default cable lengths. *)
type location = { lat : float ; lon : float }

(** {2 Devices}
 *
 * Devices are what can be created with the API or the UI, and what is saved. *)
type device = ..

(** {2 Events}
 * They are callbacks depending on a power source.
 * They are scheduled at a particular time (relative to the simulation they
 * belong to). *)
module Events = Map.Make (struct
    type t = Time.t
    let compare (a : t) (b : t) = Time.compare a b
end)

type event = power * (unit -> unit)

(** {2 Simulation}
 * A simulation is a clock and a set of scheduled events.
 * It also carries all the widgets/power sources used to represent and act
 * on it. *)

and simulation =
    { (* Stable identifier *)
      id : int ;
      (* Only a label. The root widget of this simulation carries it too, and
       * the two are renamed together (see [rename]). *)
      mutable name : string ;
      (* The root of this simulation's widget tree, and its inventory: every
       * widget of this simulation is somewhere below it.
       * Also provides the "mains": the default source of power for that
       * simulation. *)
      root : widget ;
      (* The clock: the current simulated time, and everything waiting to
       * happen, soonest first.
       *
       * [now] is a ref rather than a field so that the root widget's logger can
       * share it: the logger has to be given a way to read the time when the
       * widget is built, which is before this record exists. *)
      now : Time.t ref ;
      (* The number the next message logged anywhere in this simulation will
       * carry, which is what a reader of its logs keeps its place by. *)
      log_seq : int ref ;
      (* Every event waiting to happen, soonest first, each with the power
       * source that pays for it. *)
      mutable events : event Events.t ;
      mutable thread : Thread.t option ;
      (* Protects everything this simulation owns. It is held for the whole of
       * an event dispatch, which is what gives a thread borrowing this
       * simulation (see [Simulation.with_lock]) a consistent view: it never
       * observes a state halfway through a handler.
       *
       * It is *re-entrant* (see [lock_owner] and [with_lock]). It has to be:
       * a handler runs holding it and goes on to call [now] and [at], which
       * want it too, and a handler that walks every simulation necessarily
       * reaches its own, which it is already dispatching. Re-entrance also
       * makes those inner calls free -- they take no mutex at all -- while
       * still letting a thread from outside acquire it in the ordinary way,
       * with no invariant for callers to remember. *)
      lock : Mutex.t ;
      cond : Condition.t ;
      (* Which thread holds [lock], if any. Must be cleared before releasing the
       * mutex to wait on [cond], and restored on waking. *)
      mutable lock_owner : int option ;
      (* Whether this simulation follows the wall clock. A simulation talking to
       * the outside world must; a closed one need not, and then runs as fast as
       * it can. *)
      mutable realtime : bool ;
      (* The instant of the world outside that this simulation calls time
       * zero. Every [Time.t] of this simulation is counted from here, in
       * picoseconds.
       * Read from the wall clock when the simulation is made, and moved only
       * by [make_realtime].
       *
       * Everything the outside world dates (such as timestamps of captured
       * traffic) has to cross that gap before this simulation can use it. *)
      mutable epoch : Wall.t ;
      (* [continue] and [paused] both mean "not running", but differ in kind.
       * Clearing [continue] *ends* the simulation: [run] returns, its thread
       * finishes, and nothing sets it back -- that is what SIGINT and [stop]
       * do. Setting [paused] merely *suspends* it: the thread stays inside
       * [run] dispatching nothing, simulated time stands still, the wall clock
       * time spent that way accumulates in [paused_total] so that resuming does
       * not make time leap forward, and [resume] undoes it. *)
      mutable continue : bool ;
      mutable paused : bool ;
      (* When paused, when (wall clock) we were paused: *)
      mutable paused_since : Wall.t option ;
      (* How much wall clock time this simulation has spent paused, in total.
       * Subtracted from the wall clock when synchronising, so that resuming
       * a realtime simulation does not make the simulation time leap forward
       * and fire every pending event at once. *)
      mutable paused_total : Interval.t ;
      (* When > 0, run that many events then pause again: *)
      mutable steps : int ;
      (* Whether this simulation's network has been changed -- a device added
       * or taken out, a property set -- since it was last written out or read
       * in. It answers the one question the administration interface asks
       * about a network it did not build: is there anything in it worth
       * saving?
       *
       * Only what comes through that interface moves it: a program building a
       * network is not asked whether it wants to keep it. *)
      mutable unsaved : bool ;
      (* Non-realtime only: how fast simulated time is to advance compared to
       * the wall clock -- 1. for real time, .5 for half of it, 2. for twice as
       * fast. [None] is as fast as it can, which is what a closed simulation
       * does when nobody asks for anything else.
       *
       * Pausing leaves it alone, so that unpausing goes back to the speed that
       * was in use: it is the simulation that remembers it, not whoever paused
       * it. *)
      mutable speed_ratio : float option ;
      (* Where the pace is measured from: the wall clock time (the float, as
       * [Unix.gettimeofday] gives it) and the simulated time (the [Time.t]),
       * both read at the same instant when the anchor was set. An event due at
       * simulated time [ts] is then due, by the wall clock, at
       * [wall +. (ts -. sim) /. ratio].
       *
       * Measured from an anchor rather than event by event: per event, every
       * dispatch that ran late would push the next one later still, and a
       * simulation that fell behind would stay behind instead of catching up.
       * Set afresh whenever the speed changes or the simulation resumes --
       * neither of which is the simulation being late. *)
      mutable pace_anchor : (Wall.t * Time.t) option ;
      (* How far behind that pace the simulation is: zero while it keeps up,
       * growing while it cannot go as fast as it was asked to. *)
      mutable late : Interval.t ;
      (* How often, in *simulated* time, every metric of this simulation is
       * written down. A plot of a simulation is drawn against that
       * simulation's own clock, so the samples must be spaced along it too: a
       * simulation running as fast as it can would otherwise be sampled at
       * whatever irregular intervals the wall clock happened to catch it at.
       *
       * The cost follows from that: a simulation running N times faster than
       * real time writes N/rate snapshots per wall second, each proportional
       * to the number of metric rows it has. Lower the rate for a big network
       * watched at speed. *)
      mutable metrics_sample_rate : Interval.t ;
      (* The snapshots kept, oldest overwritten first, [None] where none has
       * been written yet. How many are kept is the length of this array --
       * there is no second field to disagree with it; see
       * [set_metrics_max_samples].
       *
       * Memory is that count times the number of metric rows, so one or the
       * other has to give on a large network. *)
      mutable metric_samples : sample option array ;
      (* Where the next snapshot goes, which is also the oldest one. *)
      mutable metric_samples_next : int ;
      (* The simulated time the next snapshot is due at. *)
      mutable metric_samples_due : Time.t }

(* What every metric of a simulation was worth at one instant, keyed by the
 * widget that owns it, the property it is read through, and the parameters of
 * the events it counts -- a hub counts its bytes per port, so that triple is
 * what identifies one series among the rest.
 *
 * [taken] is the simulated time the snapshot was taken at, which is the time
 * of the event about to be dispatched: everything strictly before it has
 * happened, and nothing at it has. It is on or after the instant the snapshot
 * was due, never before, and the two differ by however long the simulation had
 * nothing to do. *)
and sample =
    { taken : Time.t ;
      values : (int * string * Metric.Params.t, Metric.value) Hashtbl.t }

(* {2 Power sources}
 *
 * What a widget schedules on, and what deciding it is off withdraws. Several
 * widgets draw on one -- a box and its parts -- and switching it is what
 * switching them all is. *)
and power =
    { (* Whether this source may pay for events.
       *
       * Flip it only through [Simulation.power_up] and
       * [Simulation.power_down]: the dispatcher does not look at this field,
       * so switching it off without withdrawing the queued events leaves them
       * to fire, and the widgets drawing on it are not told. *)
      mutable on : bool ;
      (* What to call it, which is the full name of the widget that minted it,
       * and is what the logs say when an event is dropped for want of it. *)
      name : string ;
      (* Which simulation this power source (and, by extension, the widgets
       * using it) belongs to. *)
      sim : simulation }

and property = { name : string ;
                descr : string ;
                units : string ;
               getter : (unit -> value) ;
               (* If that property can be set *)
               setter : (value -> unit) option ;
               (* Some properties are settable only some of the time: *)
              can_set : (unit -> bool) ;
               (* The metric this property reads, when it reads one. The getter
                * renders it for display and the kind says so; this is the
                * thing itself, for whoever wants its figures rather than their
                * rendering -- the sampler that keeps a history of them does,
                * and reading them back out of the getter's JSON would be
                * absurd. *)
               metric : Metric.metric option ;
               (* What the value looks like, so that the UI can offer the right
                * input and reject nonsense before submitting it. Values still
                * travel as strings: this only says how to render one. *)
                 kind : kind ;
               (* Whether a row of the property panel is worth spending on this
                * when it reads as nothing.
                *
                * Absence usually says something: a DHCP server that serves no
                * gateway is configured that way, and the reader has to be able
                * to see it. But a property every widget carries whether or not
                * it means anything for that widget -- where it is on the map --
                * says nothing at all when it is absent, and there are two of
                * those on every widget in the tree. Those are the ones this is
                * for. *)
               only_when_set : bool }

(* A property value, in the shape the administration interface speaks.
 *
 * Not a string: properties exist only for that interface, so its own type is
 * their natural one, and keeping values typed all the way to the setter spares
 * every property author from inventing a string encoding -- and from getting it
 * wrong, which is easier than it sounds (string_of_float renders 5. as "5.",
 * which is not a number any browser will accept).
 *
 * [Basic] rather than [Safe]: the three extra constructors Safe carries --
 * Intlit, Tuple, Variant -- cannot mean anything here, and would only show up
 * as dead branches, or worse, be swallowed by a catch-all. *)
and value = Yojson.Basic.t

and kind =
    | String
    (* A string of more than one line: what a note says, and anything else
     * written in prose rather than filled in. The same string on the wire and
     * to the setter as a [String] is; what it tells the interface is how much
     * room to give it. *)
    | Text
    (* A string naming a file of the pcap library ([Pcap.Library]): the one a
     * recorder is writing, or the one a replayer is playing.
     *
     * A name and not a path -- the library is one flat directory, and a name
     * is the same string wherever it appears: in the property, in the library
     * listing, and in the file saved out of it. Fetching that file, adding one
     * and removing one are the library's business and not the widget's, so
     * what this kind tells the interface is which files to offer here, and
     * that the value is one it can hand back (null) to be done with it. *)
    | FileName
    | Int
    | Float
    (* "true" or "false", as the setter reads them *)
    | Bool
    (* One of those values, and nothing else *)
    | Enum of string array
    (* Any number of those values, each at most once, in no order of its own:
     * the interface ticks them, and the value is the places of the ticked ones
     * (as [Enum]'s is the place of the one), which is a [`List] on the wire.
     *
     * Not a [List (Enum ...)], although that is the same thing on the wire: a
     * list is a sequence, and offers the reader what a sequence is for --
     * carrying an element about, holding the same one twice -- neither of
     * which means anything about a set. What the accepted speeds of an
     * interface are is a set; what a routing table is, is a list. *)
    | Set of string array
    (* The id of another widget of the same simulation: what a cable's two ends
     * are. Not an [Int], although that is what travels: the UI has the widgets
     * of the simulation in hand and can offer them by name, which no number box
     * can do. *)
    | Widget_id
    (* A number known to lie within those bounds *)
    | FRange of float * float
    | IRange of int * int
    (* A family of counts or measures, keyed by the parameters of the events
     * they come from: it reads as a small table, and the only thing a write
     * does is reset it. Which sort of metric it is comes with the value, which
     * a metric, unlike a range, describes itself. *)
    | Metric
    (* A value that may be absent, which is [`Null] on the wire. Build one with
     * [optional] rather than by hand, so that the combinations that mean
     * nothing cannot be written. *)
    | Optional of kind
    (* Any number of values of the same kind, in order, which is a [`List] on
     * the wire. The interface draws it as a column of inputs, or as a table
     * when what is repeated is a record. Build one with [list]. *)
    | List of kind
    (* A fixed set of named values, which is an [`Assoc] on the wire. The
     * interface draws it as a row of named inputs, and as one row of the table
     * when it is what a list repeats.
     *
     * An array rather than an association list because the order is the order
     * of the columns: it is decided once, by whoever declares the property,
     * and every value of that property is then laid out the same way. Build
     * one with [record]. *)
    | Record of (string * kind) array
    (* A value written a particular way, with an example of it: what the
     * interface shows in the input while it is empty. Not a kind of its own --
     * it is one more thing said about the value inside it -- and where a
     * description explains what a value is for, this shows what one looks
     * like. Build one with [hint]. *)
    | Hint of string * kind

(* {2 Widgets}
 *
 * Anything with a visible presence in the simulation and with which the user
 * can interact (in the UI or via the API): a host, a switch...
 * Widgets form a hierarchy (with parents/children/peers) that helps navigating
 * the network (also used to give a path-name to widgets). *)
and widget =
    { (* The stable identity of a widget. *)
      id : int ;
      (* A mere label. Must not contain '/' and be distinct than that of siblings
       * so that [full_name] stays unambiguous.
       * Mutable because unicity is also enforced when a widget moves. *)
      mutable name : string ;
      mutable parent : widget option ;
      mutable children : widget list ;
      mutable peers : peer list ;
      mutable location : location option ;
      logger : Log.t ;
      (* Where a cable reaches the device this widget stands for, if anywhere *)
      mutable ports : ports ;
      (* What kind of device this widget stands for -- "host", "switch" --
       * named the way the catalogue of buildable devices names it (see
       * [Device.all]), or [None] when the widget is a *part* of a device
       * rather than a whole one: an adapter, a router's interface, a server
       * running on a host. *)
      mutable device_type : string option ;
      (* The device itself, set by the same constructor that sets
       * [device_type], so that a widget can be turned back into the thing it
       * stands for -- a program that has just built a host through the
       * catalogue gets a widget, and wants somewhere to run a ping.
       *
       * [None] for a widget that is a part rather than a whole, as
       * [device_type] is, and for one whose module has nothing to hand back:
       * the localhost has no host record of its own, only a transceiver. *)
      mutable device : device option ;
      (* What this device was built from: every parameter the catalogue entry
       * named by [device_type] declares, coerced, in the order it declares
       * them.
       * [None] until [Device.make] fills it in, and for ever after for a
       * device wired up by hand, calling the constructors and [Eth.Cable.plug]
       * directly.
       *
       * This and not [device_type] is what says whether a widget can be built
       * again: the constructors set [device_type] themselves, so a hand-wired host
       * answers "host" as much as any other, and what it cannot say is with
       * which arguments. Hence the option, and hence a save that leaves such a
       * device out rather than guessing.
       *
       * A constructor that *chooses* -- the first free port, an address drawn
       * at random -- records what it chose here itself, and [Device.make]
       * fills this in only when it was left empty: replaying the arguments as
       * they were given would choose again, and differently. *)
      mutable made_with : (string * value) list option ;
      (* How to stop the thing this widget stands for, called by [destroy]
       * before the widget leaves the tree: cut its power, unplug the cable.
       * Set by whoever built that thing, since nothing else knows how to stop
       * it -- and only by whoever gave it its own power supply, so that
       * deleting one of several devices sharing a supply does not switch off
       * the others.
       *
       * Nothing here undoes the wiring *within* a device: its trxs point at
       * one another and at nothing else, so they go when the last reference to
       * them does. Only cables cross from one device to another, and only they
       * have to be told. *)
      mutable on_delete : unit -> unit ;
      (* The power source this widget draws on: its own if it minted one, and
       * otherwise its parent's, which is the mains of its simulation unless
       * something between the two minted one. A box is therefore a subtree
       * that shares a source, without anybody having to hand it down.
       *
       * Everything this widget schedules must draw on this one, or switching
       * it off would leave events behind. *)
      mutable power : power ;
      (* Whether this widget is the one that minted [power], as against having
       * it from above. Only an owner gets a switch in the interface: two
       * switches for one source is the confusion this whole arrangement is
       * there to end. *)
      mutable owns_power : bool ;
      (* What this widget does when its source is switched on and off. Called
       * by [Simulation.power_up] and [Simulation.power_down], which find the
       * widgets of a source by walking the tree: nothing registers, and
       * nothing has to be unregistered when a widget is destroyed or moved.
       *
       * A [power_down] must not schedule anything: by the time it is called
       * the source is off and [Simulation.at] refuses it. *)
      mutable power_up : unit -> unit ;
      mutable power_down : unit -> unit ;
      (* What went wrong the last time this widget was switched, if anything.
       *
       * Switching a source is not an operation that can be refused: it is a
       * switch. But what a widget does about it can fail -- a portal opens an
       * interface of the machine, which may not be there -- and the failure
       * has to go somewhere other than out of the switch. So it lands here,
       * and is read through the "error" property beside it: nothing in the
       * simulator has an error to handle, the interface has something to show
       * against the widget, and the reader can try the switch again as often
       * as they like. Cleared by a switching that goes through. *)
      mutable error : string option ;
      (* Setter and getter of configurable properties: *)
      mutable properties : property list }

and peer = { widget : widget ;
             via : widget option }

(* From a high-level perspective (the API), a cable reaches "port n of device d",
 * not some internal TRX. Ports are a way to designate and reach those user
 * visible sockets where a cable can be attached.
 *
 * A device made of other devices answers by calling theirs, and in doing so
 * decides which of its parts each of its port numbers reaches. That decision is
 * the point. A gateway is a router, a hub and a server wired together, and
 * offers two ports -- the outside and the LAN -- while every other end inside it
 * is already spoken for.
 *
 * Most widgets have none. *)
and ports =
    { (* How many cables the device takes. *)
      count : unit -> int ;
      (* Whether port [n] has one already. *)
      is_connected : int -> bool ;
      (* Port [n], as something to plug a cable into. *)
      dev : int -> Tools.dev ;
      (* The widget port [n] really belongs to, which is what a cable joining it
       * is recorded as reaching: a host's adapter rather than the host, a
       * router's interface rather than the router. Itself, for a device whose
       * ports are not widgets of their own -- a hub's and a switch's are
       * interchangeable, and a number for them would mean nothing. *)
      owner : int -> widget ;
      (* Undo what plugging a cable into port [n] did: the port stops emitting
       * and says it is free again. There is no way back through [dev], since
       * installing a reader is what marks a port connected in the first place,
       * so the device has to offer the way out as well as the way in. *)
      disconnect : int -> unit ;
      (* When connecting two devices, they oftentimes had a brief communication
       * to negotiate some shared characteristics depending on each end's
       * capabilities. This is performed instantly when connecting them thanks
       * to those two functions: *)
      get_capabilities : int -> Capabilities.t ;
      set_capabilities : int -> Capabilities.t -> unit }
