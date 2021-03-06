const mongoose = require('mongoose');

const Podcast = mongoose.model('Podcast');
const Video = mongoose.model('Video');
const User = mongoose.model('User');

exports.addPodcast = (req, res) => {
  if (req.user.level === 10) {
    res.render('editPodcast', { title: 'Add Podcast' });
  } else {
    req.flash('error', 'You do not have permissions to do that');
    res.redirect('/');
  }
};

exports.createPodcast = async (req, res) => {
  req.body.author = req.user._id;
  const podcast = await new Podcast(req.body).save();
  req.flash('success', `Successfully added ${podcast.name}.`);
  res.redirect(`/podcast/${podcast.slug}`);
};

exports.delete = async (req, res) => {
  if (req.user === undefined) {
    return res.sendStatus(404);
  } else if (req.user.level === 10 && req.params.id) {
    const podcast = await Podcast.findOne({ _id: req.params.id });
    podcast.remove();
    req.flash('success', 'Podcast deleted successfully');
    res.redirect('/ataraxia/podcasts');
    return User.update(
      {},
      { $pull: { hearts: { $in: [req.params.id] } } },
      { multi: true }
    );
  }
};

exports.getPodcast = async (req, res) => {
  const page = req.params.page || 1;
  const limit = 9;
  const skip = page * limit - limit;

  // 1. Query the database for a list of all podcast
  const podcastsPromise = Podcast.find()
    .skip(skip)
    .limit(limit)
    .sort({ created: 'desc' });

  const countPromise = Podcast.count();

  const [podcasts, count] = await Promise.all([podcastsPromise, countPromise]);
  const pages = Math.ceil(count / limit);
  if (!podcasts.length && skip) {
    req.flash(
      'info',
      `Hey! You asked for page ${page}. But that doesn't exist. So I put you on page ${pages}`
    );
    res.redirect(`/podcasts/page/${pages}`);
    return;
  }

  res.render('podcasts', { title: 'Podcast', podcasts, page, pages, count });
};

const confirmOwner = (podcast, user, req, res) => {
  if (!podcast.author.equals(user._id) && req.user.level !== 10) {
    req.flash('error', 'You do not have permissions to do that.');
    res.redirect('/');
  }
};

exports.editPodcast = async (req, res) => {
  // 1. Find the podcast given the ID
  const podcast = await Podcast.findOne({ _id: req.params.id });
  // 2. confirm they are the owner of the podcast
  if (req.user.level === 10) {
    confirmOwner(podcast, req.user, req, res);
    // 3. Render out the edit form so the user can update their podcast
    res.render('editPodcast', {
      title: `Editing "${podcast.name}"`,
      podcast
    });
  } else {
    req.flash('error', 'You do not have permissions to do that.');
    res.redirect('/podcasts');
  }
};

exports.updatePodcast = async (req, res) => {
  // find and update the podcast
  const podcast = await Podcast.findOneAndUpdate(
    { _id: req.params.id },
    req.body,
    {
      new: true, // return the new podcast instead of the old one
      runValidators: true
    }
  ).exec();
  req.flash(
    'success',
    `<strong>${
      podcast.name
    }</strong> is updated successfully. <a href="/podcast/${
      podcast.slug
    }">See The Podcast →</a>`
  );
  res.redirect(`/ataraxia/podcasts/${podcast.id}/edit`);
  // Redriect them the podcast and tell them it worked
};

exports.getPodcastBySlug = async (req, res, next) => {
  const podcast = await Podcast.findOne({ slug: req.params.slug }).populate(
    'author reviews'
  );
  if (!podcast) return next();
  res.render('podcast', { podcast, title: podcast.name });
};

exports.getPodcastsByTag = async (req, res) => {
  const tag = req.params.tag;
  const tagQuery = tag || { $exists: true };

  const tagsPromise = Podcast.getTagsList();
  const podcastsPromise = Podcast.find({ tags: tagQuery });

  const videoTagsPromise = Video.getTagsList();
  const videosPromise = Video.find({ tags: tagQuery });

  const [tags, podcasts, tags2, videos] = await Promise.all([
    tagsPromise,
    podcastsPromise,
    videoTagsPromise,
    videosPromise
  ]);
  res.render('tag', { tags, tags2, title: 'Tags', tag, podcasts, videos });
};
