const LOG_SEVERE = java.util.logging.Level.SEVERE
const LOG_WARNING = java.util.logging.Level.WARNING
const LOG_INFO = java.util.logging.Level.INFO
const LOG_FINE = java.util.logging.Level.FINE
const LOG_FINER = java.util.logging.Level.FINER
const LOG_FINEST = java.util.logging.Level.FINEST

const SUCCESS = "SUCCESS"
const ERROR = "ERROR"
const WARN = "WARN"
const LOG = "LOG"
const CONTEXT = "CONTEXT"
const DEBUG = "DEBUG"
const VERBOSE = "VERBOSE"

const LOG_LEVELS = {
    SUCCESS: LOG_SEVERE,
    ERROR: LOG_SEVERE,
    WARN: LOG_WARNING,
    LOG: LOG_INFO,
    CONTEXT: LOG_FINE,
    DEBUG: LOG_FINER,
    VERBOSE: LOG_FINEST
}

const LOGGER_NAME = "Verify_Access_Logger"
const LOGGER_VERSION = "1.0.0"

function getDetailedTimestamp() {
    // Format aligned to what Logstash expects.
    var ts = new Date();
    return ("0" + ts.getDate()).slice(-2) + "/" + ("0" + (ts.getMonth() + 1)).slice(-2) + "/" + ts.getFullYear() + "T" + ("00" + ts.getHours()).slice(-2) + ":" + ("00" + ts.getMinutes()).slice(-2) + ":" + ("00" + ts.getSeconds()).slice(-2) + "." + ("000" + ts.getMilliseconds()).slice(-3);
}

const LOG_OBJECT = {
    correlation: "" + java.util.UUID.randomUUID(), // Transaction ID.
    program: "", // Setup when the object is initialised.
    init: new Date(), // Timestamp logger was initialized.
    lastTime: new Date(), // Timestamp of last time a logger.log() was written.
    timers: {},
    timerResults: {},

    /**
     * Logger tracing function to print messages to the `trace.log` file.
     * @param {keyof LOG_LEVELS} eventId One of the defined Logger event IDs
     * @param {String} message 
     */
    log: function (eventId, message) {
        message = message || "";
        currentTime = new Date();
        output = {
            "time": "" + getDetailedTimestamp(),
            "delta": currentTime - this.lastTime,
            "total": currentTime - this.init,
            "inst": "" + this.program,
            "msg": "" + eventId,
            "correlation": this.correlation,
            "details": "" + message
        }
        for (result in this.timerResults) {
            output["timer_" + result] = this.timerResults[result]
        }
        IDMappingExtUtils.traceString("##" + LOGGER_NAME + "_ver=" + LOGGER_VERSION + "##" + JSON.stringify(output), LOG_LEVELS[eventId]);
        this.lastTime = currentTime;
    },

    /**
     * Initiates timer function.
     * @param {String} name Name of timer
     */
    startTimer: function (name) {
        this.timers[name] = new Date();
    },

    /**
     * Records the result of `startTimer()` in milliseconds.
     * @param {string} name Name of the timer
     */
    stopTimer: function (name) {
        if (this.timers.hasOwnProperty(name)) {
            var stopTimerResult = new Date() - this.timers[name];
            this.timerResults[name] = stopTimerResult;
        }
    }
}

// Initialises logging object.
logger = Object.create(LOG_OBJECT);