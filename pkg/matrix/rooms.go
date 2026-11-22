package matrix

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Room describes a Matrix room and its current state.
type Room struct {
	ID        id.RoomID
	Name      string
	Alias     id.RoomAlias
	Encrypted bool
}

func validateRoom(room string) error {
	if len(room) < 2 || strings.ContainsAny(room, " \t\r\n\x00") ||
		(room[0] != '!' && room[0] != '#') {
		return errors.New("enter a room ID starting with ! or a room alias starting with #")
	}
	if room[0] == '#' {
		local, server, found := strings.Cut(room[1:], ":")
		if !found || local == "" || server == "" {
			return errors.New("a room alias must have the form #name:server")
		}
	}
	return nil
}

func resolve(ctx context.Context, cli *mautrix.Client, room string) (id.RoomID, []string, error) {
	if room[0] == '!' {
		return id.RoomID(room), nil, nil
	}
	resp, err := cli.ResolveAlias(ctx, id.RoomAlias(room))
	if err != nil {
		return "", nil, requestError("resolve the room alias", err)
	}
	if resp == nil || !strings.HasPrefix(resp.RoomID.String(), "!") || validateRoom(resp.RoomID.String()) != nil {
		return "", nil, errors.New("invalid room ID in the Matrix response")
	}
	return resp.RoomID, resp.Servers, nil
}

// roomState requires a complete state response before treating a room as plaintext.
func roomState(ctx context.Context, cli *mautrix.Client, roomID id.RoomID) (mautrix.RoomStateMap, error) {
	var events []*event.Event
	_, err := cli.MakeRequest(ctx, "GET", cli.BuildClientURL("v3", "rooms", roomID, "state"), nil, &events)
	if err != nil {
		return nil, requestError("get the room state", err)
	}
	state := make(mautrix.RoomStateMap)
	for _, evt := range events {
		if evt == nil || evt.StateKey == nil || evt.Type.Type == "" {
			return nil, errors.New("invalid room state in the Matrix response")
		}
		evt.RoomID = roomID
		evt.Type.Class = event.StateEventType
		_ = evt.Content.ParseRaw(evt.Type)
		if state[evt.Type] == nil {
			state[evt.Type] = map[string]*event.Event{}
		}
		state[evt.Type][evt.GetStateKey()] = evt
	}
	if state[event.StateCreate][""] == nil {
		return nil, errors.New("incomplete room state in the Matrix response")
	}
	return state, nil
}

func describeRoom(roomID id.RoomID, state mautrix.RoomStateMap) Room {
	r := Room{ID: roomID, Encrypted: state[event.StateEncryption][""] != nil}
	if evt := state[event.StateRoomName][""]; evt != nil {
		r.Name = evt.Content.AsRoomName().Name
	}
	if evt := state[event.StateCanonicalAlias][""]; evt != nil {
		r.Alias = evt.Content.AsCanonicalAlias().Alias
	}
	return r
}

func (s *Service) withClient(ctx context.Context, op func(*session, *mautrix.Client) error) error {
	return s.withSession(ctx, func(sess *session, cli *mautrix.Client) error {
		if err := s.refresh(ctx, sess, cli); err != nil {
			return err
		}
		return op(sess, cli)
	})
}

// RoomInfo returns the room ID, canonical alias, name, and encryption status.
func (s *Service) RoomInfo(ctx context.Context, room string) (result Room, err error) {
	if err := validateRoom(room); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	err = s.withClient(ctx, func(_ *session, cli *mautrix.Client) error {
		roomID, _, err := resolve(ctx, cli, room)
		if err != nil {
			return err
		}
		state, err := roomState(ctx, cli, roomID)
		if err == nil {
			result = describeRoom(roomID, state)
		}
		return err
	})
	return result, err
}

// ListRooms returns the joined rooms, ordered by room ID.
func (s *Service) ListRooms(ctx context.Context) (rooms []Room, err error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	err = s.withClient(ctx, func(_ *session, cli *mautrix.Client) error {
		resp, err := cli.JoinedRooms(ctx)
		if err != nil {
			return requestError("list joined rooms", err)
		}
		if resp == nil {
			return errors.New("missing room list in the Matrix response")
		}
		slices.Sort(resp.JoinedRooms)
		for _, roomID := range resp.JoinedRooms {
			state, err := roomState(ctx, cli, roomID)
			if err != nil {
				return err
			}
			rooms = append(rooms, describeRoom(roomID, state))
		}
		return nil
	})
	return rooms, err
}

// JoinRoom joins a room by ID or alias and returns its ID.
func (s *Service) JoinRoom(ctx context.Context, room string) (joined id.RoomID, err error) {
	if err := validateRoom(room); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	err = s.withClient(ctx, func(_ *session, cli *mautrix.Client) error {
		roomID, via, err := resolve(ctx, cli, room)
		if err != nil {
			return err
		}
		if len(via) == 0 {
			// Older room IDs carry a server name that can route a remote join.
			if _, server, ok := strings.Cut(roomID.String(), ":"); ok && server != "" {
				via = []string{server}
			}
		}
		resp, err := cli.JoinRoom(ctx, roomID.String(), &mautrix.ReqJoinRoom{Via: via})
		if err != nil {
			return requestError("join the room", err)
		}
		if resp == nil || resp.RoomID != roomID {
			return errors.New("the room ID in the Matrix response does not match the requested ID")
		}
		joined = resp.RoomID
		return nil
	})
	return joined, err
}

// Send sends a text message. It never falls back to plaintext after an encryption error.
func (s *Service) Send(ctx context.Context, room, text string) (eventID id.EventID, err error) {
	if err := validateRoom(room); err != nil {
		return "", err
	}
	if strings.TrimSpace(text) == "" {
		return "", errors.New("the message must not be empty")
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	err = s.withClient(ctx, func(sess *session, cli *mautrix.Client) error {
		roomID, _, err := resolve(ctx, cli, room)
		if err != nil {
			return err
		}
		state, err := roomState(ctx, cli, roomID)
		if err != nil {
			return err
		}
		content := &event.MessageEventContent{MsgType: event.MsgText, Body: text}
		typ, payload := event.EventMessage, any(content)
		if state[event.StateEncryption][""] != nil {
			typ = event.EventEncrypted
			payload, err = s.encrypt(ctx, sess, cli, roomID, state, content)
			if err != nil {
				return err
			}
		}
		resp, err := cli.SendMessageEvent(ctx, roomID, typ, payload, mautrix.ReqSendEvent{DontEncrypt: true})
		if err != nil {
			return requestError("send the message", err)
		}
		if resp == nil || resp.EventID == "" {
			return errors.New("missing message ID in the Matrix response")
		}
		eventID = resp.EventID
		return nil
	})
	return eventID, err
}

// Message is a room message or a marker for an encrypted event without readable content.
type Message struct {
	ID            id.EventID
	Sender        id.UserID
	Time          time.Time
	Body          string
	Undecryptable bool
}

// Read returns up to limit recent messages in chronological order.
func (s *Service) Read(ctx context.Context, room string, limit int) (messages []Message, err error) {
	if err := validateRoom(room); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, errors.New("the read limit must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	err = s.withClient(ctx, func(sess *session, cli *mautrix.Client) error {
		roomID, _, err := resolve(ctx, cli, room)
		if err != nil {
			return err
		}
		messages, err = s.readHistory(ctx, sess, cli, roomID, limit)
		return err
	})
	return messages, err
}
