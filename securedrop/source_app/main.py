import operator
import os
import io

from base64 import urlsafe_b64encode
from datetime import datetime
from typing import Union

import werkzeug
from flask import (Blueprint, render_template, flash, redirect, url_for, g,
                   session, current_app, request, Markup, abort)
from flask_babel import gettext
from sqlalchemy.exc import IntegrityError

import store

from db import db
from models import Source, Submission, Reply, get_one_or_else
from sdconfig import SDConfig
from source_app.apiv2 import TOKEN_EXPIRATION_MINS
from source_app.decorators import login_required
from source_app.utils import (logged_in, generate_unique_codename,
                              normalize_timestamps, valid_codename)
from source_app.forms import LoginForm, SubmissionForm


def make_blueprint(config: SDConfig) -> Blueprint:
    view = Blueprint('main', __name__)

    @view.route('/')
    def index() -> str:
        return render_template('index.html')

    @view.route('/generate', methods=('GET', 'POST'))
    def generate() -> Union[str, werkzeug.Response]:
        if logged_in():
            flash(gettext(
                "You were redirected because you are already logged in. "
                "If you want to create a new account, you should log out "
                "first."),
                  "notification")
            return redirect(url_for('.lookup'))

        codename = generate_unique_codename(config)

        # Generate a unique id for each browser tab and associate the codename with this id.
        # This will allow retrieval of the codename displayed in the tab from which the source has
        # clicked to proceed to /generate (ref. issue #4458)
        tab_id = urlsafe_b64encode(os.urandom(64)).decode()
        codenames = session.get('codenames', {})
        codenames[tab_id] = codename
        session['codenames'] = codenames

        session['new_user'] = True
        return render_template('generate.html', codename=codename, tab_id=tab_id)

    @view.route('/create', methods=['POST'])
    def create() -> werkzeug.Response:
        if session.get('logged_in', False):
            flash(gettext("You are already logged in. Please verify your codename above as it " +
                          "may differ from the one displayed on the previous page."),
                  'notification')
        else:
            tab_id = request.form['tab_id']
            codename = session['codenames'][tab_id]
            session['codename'] = codename

            del session['codenames']

            filesystem_id = current_app.crypto_util.hash_codename(codename)
            try:
                source = Source(filesystem_id, current_app.crypto_util.display_id())
            except ValueError as e:
                current_app.logger.error(e)
                flash(
                    gettext("There was a temporary problem creating your account. "
                            "Please try again."
                            ),
                    'error'
                )
                return redirect(url_for('.index'))

            db.session.add(source)
            try:
                db.session.commit()
            except IntegrityError as e:
                db.session.rollback()
                current_app.logger.error(
                    "Attempt to create a source with duplicate codename: %s" %
                    (e,))

                # Issue 2386: don't log in on duplicates
                del session['codename']

                # Issue 4361: Delete 'logged_in' if it's in the session
                try:
                    del session['logged_in']
                except KeyError:
                    pass

                abort(500)
            else:
                os.mkdir(current_app.storage.path(filesystem_id))

            session['logged_in'] = True
        return redirect(url_for('.lookup'))

    @view.route('/lookup', methods=('GET',))
    @login_required
    def lookup() -> str:
        replies = []
        source_inbox = Reply.query.filter(Reply.source_id == g.source.id) \
                                  .filter(Reply.deleted_by_source == False).all()  # noqa

        for reply in source_inbox:
            reply_path = current_app.storage.path(
                g.filesystem_id,
                reply.filename,
            )
            try:
                with io.open(reply_path, "rb") as f:
                    contents = f.read()
                reply_obj = current_app.crypto_util.decrypt(g.codename, contents)
                reply.decrypted = reply_obj
            except UnicodeDecodeError:
                current_app.logger.error("Could not decode reply %s" %
                                         reply.filename)
            except FileNotFoundError:
                current_app.logger.error("Reply file missing: %s" %
                                         reply.filename)
            else:
                reply.date = datetime.utcfromtimestamp(
                    os.stat(reply_path).st_mtime)
                replies.append(reply)

        # Sort the replies by date
        replies.sort(key=operator.attrgetter('date'), reverse=True)

        # Generate a keypair to encrypt replies from the journalist
        if not current_app.crypto_util.get_fingerprint(g.filesystem_id):
            current_app.crypto_util.genkeypair(g.filesystem_id, g.codename)

        current_app.logger.info("client needs to register still?: {}".format(
                    g.source.is_signal_registered()))

        return render_template(
            'lookup.html',
            token=session["token"],
            source_uuid=g.source.uuid,
            to_register=not g.source.is_signal_registered(),
            allow_document_uploads=current_app.instance_config.allow_document_uploads,
            codename=g.codename,
            replies=replies,
            new_user=session.get('new_user', None),
            form=SubmissionForm(),
        )

    @view.route('/submit', methods=('POST',))
    @login_required
    def submit() -> werkzeug.Response:
        allow_document_uploads = current_app.instance_config.allow_document_uploads
        form = SubmissionForm()
        if not form.validate():
            for field, errors in form.errors.items():
                for error in errors:
                    flash(error, "error")
            return redirect(url_for('main.lookup'))

        msg = request.form['msg']
        fh = None
        if allow_document_uploads and 'fh' in request.files:
            fh = request.files['fh']

        # Don't submit anything if it was an "empty" submission. #878
        if not (msg or fh):
            if allow_document_uploads:
                flash(gettext(
                    "You must enter a message or choose a file to submit."),
                      "error")
            else:
                flash(gettext("You must enter a message."), "error")
            return redirect(url_for('main.lookup'))

        fnames = []
        journalist_filename = g.source.journalist_filename
        first_submission = g.source.interaction_count == 0

        if not os.path.exists(current_app.storage.path(g.filesystem_id)):
            current_app.logger.debug("Store directory not found for source '{}', creating one."
                                     .format(g.source.journalist_designation))
            os.mkdir(current_app.storage.path(g.filesystem_id))

        if msg:
            g.source.interaction_count += 1
            fnames.append(
                current_app.storage.save_message_submission(
                    g.filesystem_id,
                    g.source.interaction_count,
                    journalist_filename,
                    msg))
        if fh:
            g.source.interaction_count += 1
            fnames.append(
                current_app.storage.save_file_submission(
                    g.filesystem_id,
                    g.source.interaction_count,
                    journalist_filename,
                    fh.filename,
                    fh.stream))

        if first_submission:
            flash_message = render_template('first_submission_flashed_message.html')
            flash(Markup(flash_message), "success")

        else:
            if msg and not fh:
                html_contents = gettext('Thanks! We received your message.')
            elif fh and not msg:
                html_contents = gettext('Thanks! We received your document.')
            else:
                html_contents = gettext('Thanks! We received your message and '
                                        'document.')

            flash_message = render_template(
                'next_submission_flashed_message.html',
                html_contents=html_contents
            )
            flash(Markup(flash_message), "success")

        new_submissions = []
        for fname in fnames:
            submission = Submission(g.source, fname)
            db.session.add(submission)
            new_submissions.append(submission)

        g.source.pending = False
        g.source.last_updated = datetime.utcnow()
        db.session.commit()

        for sub in new_submissions:
            store.async_add_checksum_for_file(sub)

        normalize_timestamps(g.filesystem_id)

        return redirect(url_for('main.lookup'))

    @view.route('/delete', methods=('POST',))
    @login_required
    def delete() -> werkzeug.Response:
        """This deletes the reply from the source's inbox, but preserves
        the history for journalists such that they can view conversation
        history.
        """

        query = Reply.query.filter_by(
            filename=request.form['reply_filename'],
            source_id=g.source.id)
        reply = get_one_or_else(query, current_app.logger, abort)
        reply.deleted_by_source = True
        db.session.add(reply)
        db.session.commit()

        flash(gettext("Reply deleted"), "notification")
        return redirect(url_for('.lookup'))

    @view.route('/delete-all', methods=('POST',))
    @login_required
    def batch_delete() -> werkzeug.Response:
        replies = Reply.query.filter(Reply.source_id == g.source.id) \
                             .filter(Reply.deleted_by_source == False).all()  # noqa
        if len(replies) == 0:
            current_app.logger.error("Found no replies when at least one was "
                                     "expected")
            return redirect(url_for('.lookup'))

        for reply in replies:
            reply.deleted_by_source = True
            db.session.add(reply)
        db.session.commit()

        flash(gettext("All replies have been deleted"), "notification")
        return redirect(url_for('.lookup'))

    @view.route('/login', methods=('GET', 'POST'))
    def login() -> Union[str, werkzeug.Response]:
        form = LoginForm()
        if form.validate_on_submit():
            codename = request.form['codename'].strip()
            if valid_codename(codename):
                session.update(codename=codename, logged_in=True)
                # TEMP (would need this on the generate route too)
                source = Source.login(codename)
                session['token'] = source.generate_api_token(expiration=TOKEN_EXPIRATION_MINS * 60)
                return redirect(url_for('.lookup', from_login='1'))
            else:
                current_app.logger.info(
                        "Login failed for invalid codename")
                flash(gettext("Sorry, that is not a recognized codename."),
                      "error")

        return render_template('login.html', form=form)

    @view.route('/logout')
    def logout() -> Union[str, werkzeug.Response]:
        """
        If a user is logged in, show them a logout page that prompts them to
        click the New Identity button in Tor Browser to complete their session.
        Otherwise redirect to the main Source Interface page.
        """
        if logged_in():

            # Clear the session after we render the message so it's localized
            # If a user specified a locale, save it and restore it
            session.clear()
            session['locale'] = g.localeinfo.id
            # TODO: Invalidate token if it exists

            return render_template('logout.html')
        else:
            return redirect(url_for('.index'))

    return view
