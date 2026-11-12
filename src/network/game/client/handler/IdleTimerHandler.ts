import ClientGameMessageHandler from '#/network/game/client/ClientGameMessageHandler.js';
import IdleTimer from '#/network/game/client/model/IdleTimer.js';
import Player from '#/engine/entity/Player.js';

export default class IdleTimerHandler extends ClientGameMessageHandler<IdleTimer> {
    handle(_message: IdleTimer, _player: Player): boolean {
        // Idlescape is an idle game: the client reports that the player has stopped touching the controls,
        // and we deliberately do nothing about it. There is no AFK logout.
        return true;
    }
}
